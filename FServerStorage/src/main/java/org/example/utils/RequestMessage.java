package org.example.utils;

import java.io.Serializable;

public class RequestMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final ServiceGrantingTicket sgt;
    private final byte[] authenticator;
    private final Command command;

    public RequestMessage(ServiceGrantingTicket sgt, byte[] authenticator,Command command) {
        this.sgt = sgt;
        this.authenticator = authenticator;
        this.command = command;
    }

    public Command getCommand() {
        return command;
    }

    public ServiceGrantingTicket getSgt() {
        return sgt;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}