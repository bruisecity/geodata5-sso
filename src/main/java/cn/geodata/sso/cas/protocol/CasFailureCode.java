package cn.geodata.sso.cas.protocol;

/**
 * Failure codes emitted by the legacy CAS 3.5.2 validation specifications.
 *
 * <p>Architecture 5.2A: the code values must stay identical to the legacy ones because clients
 * branch on them. These are the codes produced by
 * {@code ServiceTicketImpl} / {@code Cas20WithoutProxyingValidationSpecification} /
 * {@code AbstractTicketValidationFilter} paths actually reachable in the legacy server.
 */
public enum CasFailureCode {

    /** Ticket unknown, expired, or already consumed. */
    INVALID_TICKET,

    /** Ticket exists but was issued for a different service URL. */
    INVALID_SERVICE,

    /** Ticket was used more times than allowed, or presented in the wrong state. */
    INVALID_TICKET_SPEC,

    /** Ticket has expired per the expiration policy (legacy ST policy: 1 use + 10 seconds). */
    INVALID_TICKET_STATE,

    /** Request itself is malformed: missing service/ticket parameters. */
    INVALID_REQUEST,

    /** Legacy {@code UnauthorizedServiceException} - service not registered / disabled. */
    INVALID_SERVICE_NOT_AUTHORIZED,

    /** Server-side failure while validating. */
    INTERNAL_ERROR
}
