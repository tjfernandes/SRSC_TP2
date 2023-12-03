package org.example.utils;

import java.io.Serializable;

public class RequestMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final ServiceGrantingTicket sgt;
    private final byte[] authenticator;

    public RequestMessage(ServiceGrantingTicket sgt, byte[] authenticator) {
        this.sgt = sgt;
        this.authenticator = authenticator;
    }

    public ServiceGrantingTicket getSgt() {
        return sgt;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}