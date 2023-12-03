package org.example.utils;

import java.io.Serializable;

public class RequestMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final TicketGrantingTicket tgt;
    private final String serviceId;
    private final byte[] authenticator;

    public RequestMessage(TicketGrantingTicket tgt, String serviceId, byte[] authenticator) {
        this.tgt = tgt;
        this.serviceId = serviceId;
        this.authenticator = authenticator;
    }

    public TicketGrantingTicket getTgt() {
        return tgt;
    }

    public String getServiceId() {
        return serviceId;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}