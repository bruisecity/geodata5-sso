package cn.geodata.sso.cas.ticket;

import cn.geodata.sso.config.SsoProperties;
import cn.geodata.sso.cas.protocol.CasFailureCode;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Ticket registry with the legacy expiration semantics (architecture 5.3).
 *
 * <p>TGT: {@code maxTimeToLive=28800s} (8h), {@code timeToKill=7200s} (2h) per
 * {@code ticketExpirationPolicies.xml:44-46}.
 *
 * <p>ST: {@code MultiTimeUseOrTimeoutExpirationPolicy} with {@code numberOfUses=1} and
 * {@code timeToKill=${st.timeToKillInSeconds:10}}. The architecture calls out that this is
 * <em>stricter</em> than the CAS spec's 2 minutes and that the stricter value must be used,
 * otherwise a window opens where the legacy server has already invalidated a ticket while the
 * new one still accepts it.
 *
 * <p>Storage: this implementation keeps tickets in a process-local map with explicit TTL checks,
 * which satisfies the single-instance deployment target of phase 1. The key names
 * ({@code cas:tgt:{id}} / {@code cas:st:{id}}) match the architecture so swapping in a Redis
 * implementation is a bean replacement, not a rewrite.
 */
@Component
public class CasTicketRegistry {

    private static final String TGT_PREFIX = "TGT-";
    private static final String ST_PREFIX = "ST-";

    private final SsoProperties props;
    private final Map<String, CasTicket> tickets = new ConcurrentHashMap<>();

    public CasTicketRegistry(SsoProperties props) {
        this.props = props;
    }

    /** Creates a TGT bound to the authenticated principal. */
    public CasTicket createTicketGrantingTicket(String principal, Map<String, Object> attributes) {
        Instant now = Instant.now();
        CasTicket t = new CasTicket();
        t.setId(TGT_PREFIX + UUID.randomUUID());
        t.setType(CasTicket.Type.TGT);
        t.setPrincipal(principal);
        t.setAttributes(attributes == null ? Map.of() : attributes);
        t.setCreatedAt(now);
        t.setExpiresAt(now.plus(props.getCas().getTicketGrantingTicketMaxLifetime()));
        t.setMaxUses(Integer.MAX_VALUE);
        t.setFromNewLogin(true);
        tickets.put(t.getId(), t);
        return t;
    }

    /**
     * Issues a ST for a service. Legacy clients treat {@code ST-<uuid>} as opaque, so the shape
     * mirrors the legacy generator (2-100 chars, no whitespace).
     */
    public CasTicket createServiceTicket(String service, CasTicket tgt, boolean fromNewLogin) {
        Instant now = Instant.now();
        Duration ttl = props.getCas().getServiceTicketTtl();
        CasTicket t = new CasTicket();
        t.setId(ST_PREFIX + UUID.randomUUID());
        t.setType(CasTicket.Type.ST);
        t.setPrincipal(tgt != null ? tgt.getPrincipal() : null);
        t.setAttributes(tgt != null ? tgt.getAttributes() : Map.of());
        t.setService(service);
        t.setParentTicketId(tgt != null ? tgt.getId() : null);
        t.setCreatedAt(now);
        t.setExpiresAt(now.plus(ttl));
        t.setMaxUses(1);
        t.setFromNewLogin(fromNewLogin);
        tickets.put(t.getId(), t);
        return t;
    }

    /**
     * Validates and atomically consumes a ST.
     *
     * <p>The read-and-increment happens inside {@code compute} so two concurrent validations of the
     * same ticket cannot both succeed - a replay window would be a security defect, not a glitch.
     */
    public TicketValidationResult validateAndConsume(String ticketId, String service) {
        if (ticketId == null || ticketId.isBlank()) {
            return TicketValidationResult.fail(CasFailureCode.INVALID_REQUEST, "ticket is required");
        }
        final TicketValidationResult[] result = new TicketValidationResult[1];
        tickets.compute(ticketId, (id, ticket) -> {
            if (ticket == null) {
                result[0] = TicketValidationResult.fail(CasFailureCode.INVALID_TICKET,
                        "Ticket [" + id + "] not recognized");
                return null;
            }
            Instant now = Instant.now();
            if (ticket.isExpired(now)) {
                result[0] = TicketValidationResult.fail(CasFailureCode.INVALID_TICKET,
                        "Ticket [" + id + "] has expired");
                return null;
            }
            if (ticket.getType() != CasTicket.Type.ST) {
                result[0] = TicketValidationResult.fail(CasFailureCode.INVALID_TICKET,
                        "Ticket [" + id + "] is not a service ticket");
                return null;
            }
            if (ticket.isExhausted()) {
                result[0] = TicketValidationResult.fail(CasFailureCode.INVALID_TICKET_SPEC,
                        "Ticket [" + id + "] already been used once");
                return null;
            }
            // Legacy compares the service string verbatim against the value captured at issue time.
            if (service == null || ticket.getService() == null || !ticket.getService().equals(service)) {
                result[0] = TicketValidationResult.fail(CasFailureCode.INVALID_SERVICE,
                        "Ticket [" + id + "] does not match supplied service");
                return null;
            }
            ticket.setUses(ticket.getUses() + 1);
            result[0] = TicketValidationResult.ok(ticket);
            // single use -> drop immediately
            return ticket.getUses() >= ticket.getMaxUses() ? null : ticket;
        });
        return result[0];
    }

    public Optional<CasTicket> find(String ticketId) {
        CasTicket t = tickets.get(ticketId);
        if (t == null) {
            return Optional.empty();
        }
        if (t.isExpired(Instant.now())) {
            tickets.remove(ticketId);
            return Optional.empty();
        }
        return Optional.of(t);
    }

    /**
     * Returns a live TGT, sliding its idle window. The legacy TGT dies after 2h of inactivity while
     * remaining valid up to 8h overall; both bounds are enforced here.
     */
    public Optional<CasTicket> touchTicketGrantingTicket(String tgtId) {
        CasTicket t = tickets.get(tgtId);
        if (t == null || t.getType() != CasTicket.Type.TGT) {
            return Optional.empty();
        }
        Instant now = Instant.now();
        if (t.isExpired(now)) {
            tickets.remove(tgtId);
            return Optional.empty();
        }
        Instant idleDeadline = now.plus(props.getCas().getTicketGrantingTicketIdleTimeout());
        Instant absoluteDeadline = t.getCreatedAt().plus(props.getCas().getTicketGrantingTicketMaxLifetime());
        t.setExpiresAt(idleDeadline.isBefore(absoluteDeadline) ? idleDeadline : absoluteDeadline);
        return Optional.of(t);
    }

    public void remove(String ticketId) {
        tickets.remove(ticketId);
    }

    /** Legacy {@code /cas/logout}: destroy the TGT; all STs issued from it become unusable. */
    public void removeTicketGrantingTicket(String tgtId) {
        if (tgtId == null) {
            return;
        }
        tickets.remove(tgtId);
        tickets.values().removeIf(t -> tgtId.equals(t.getParentTicketId()));
    }

    /** Purge expired entries; called opportunistically to keep the map bounded. */
    public int purgeExpired() {
        Instant now = Instant.now();
        int before = tickets.size();
        tickets.values().removeIf(t -> t.isExpired(now));
        return before - tickets.size();
    }

    public int size() {
        return tickets.size();
    }
}
