package cn.geodata.sso.cas.ticket;

import cn.geodata.sso.cas.protocol.CasFailureCode;

/**
 * Result of a ticket validation attempt.
 *
 * <p>Carries a {@link CasFailureCode} rather than throwing, because the legacy server converted
 * every failure into a protocol-level response body (never an HTTP 500), and clients depend on
 * receiving a parseable failure rather than a transport error.
 */
public final class TicketValidationResult {

    private final boolean success;
    private final CasTicket ticket;
    private final CasFailureCode failureCode;
    private final String description;

    private TicketValidationResult(boolean success, CasTicket ticket, CasFailureCode code, String description) {
        this.success = success;
        this.ticket = ticket;
        this.failureCode = code;
        this.description = description;
    }

    public static TicketValidationResult ok(CasTicket ticket) {
        return new TicketValidationResult(true, ticket, null, null);
    }

    public static TicketValidationResult fail(CasFailureCode code, String description) {
        return new TicketValidationResult(false, null, code, description);
    }

    public boolean isSuccess() {
        return success;
    }

    public CasTicket getTicket() {
        return ticket;
    }

    public CasFailureCode getFailureCode() {
        return failureCode;
    }

    public String getDescription() {
        return description;
    }
}
