package org.example.utils;

import java.io.Serial;
import java.io.Serializable;

public class RequestedMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String serviceId;
    private final int nonce;

    public RequestedMessage(String clientId, String serviceId, int nonce) {
        this.clientId = clientId;
        this.serviceId = serviceId;
        this.nonce = nonce;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getServiceId() {
        return this.serviceId;
    }

    public int getNonce() {
        return nonce;
    }
}
