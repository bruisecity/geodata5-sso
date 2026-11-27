package cn.geodata.sso.cas.ticket;

import java.io.Serializable;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory / Redis representation of a CAS ticket.
 *
 * <p>Architecture 5.3 decides CAS tickets are <em>not</em> expressed as
 * {@code OAuth2Authorization} records: the CAS TGT/ST semantics (single use, 10-second window,
 * bound to a service URL) differ from OAuth authorization-code semantics, and fusing the two
 * lifecycles would entangle them. They carry their own TTL and only share the user domain.
 */
public class CasTicket implements Serializable {

    private static final long serialVersionUID = 1L;

    public enum Type {
        TGT,
        ST
    }

    private String id;
    private Type type;
    /** Username the ticket was issued for (the legacy {@code principal.id}). */
    private String principal;
    /** Service URL bound at issue time; null for TGT. */
    private String service;
    /** Set on the TGT so a ST can be traced back to the session that created it. */
    private String parentTicketId;
    private Instant createdAt;
    private Instant expiresAt;
    private int uses;
    private int maxUses = 1;
    /** Snapshot of principal attributes so validation does not need the legacy DB again. */
    private Map<String, Object> attributes = new LinkedHashMap<>();
    /** Whether the ticket came from a {@code renew} request (affects gateway semantics). */
    private boolean fromNewLogin;

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public boolean isExpired(Instant now) {
        return expiresAt != null && now.isAfter(expiresAt);
    }

    public boolean isExhausted() {
        return uses >= maxUses;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Type getType() {
        return type;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public String getParentTicketId() {
        return parentTicketId;
    }

    public void setParentTicketId(String parentTicketId) {
        this.parentTicketId = parentTicketId;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public int getUses() {
        return uses;
    }

    public void setUses(int uses) {
        this.uses = uses;
    }

    public int getMaxUses() {
        return maxUses;
    }

    public void setMaxUses(int maxUses) {
        this.maxUses = maxUses;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public boolean isFromNewLogin() {
        return fromNewLogin;
    }

    public void setFromNewLogin(boolean fromNewLogin) {
        this.fromNewLogin = fromNewLogin;
    }
}
