package org.example.utils;

import java.io.Serializable;

public class RequestTGSMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] tgt;
    private final String serviceId;
    private final byte[] authenticator;


    public RequestTGSMessage(byte[] tgt, String serviceId, byte[] authenticator) {
        this.tgt = tgt;
        this.serviceId = serviceId;
        this.authenticator = authenticator;
    }

    public byte[] getTgt() {
        return tgt;
    }

    public String getServiceId() {
        return serviceId;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}