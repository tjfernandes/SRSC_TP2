package org.example.utils;

import java.io.Serial;
import java.io.Serializable;

public class RequestMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String serviceId;
    private final String clientAddress;
    private final int nonce;

    public RequestMessage(String clientId,String clientAddress ,String serviceId, int nonce) {
        this.clientId = clientId;
        this.serviceId = serviceId;
        this.nonce = nonce;
        this.clientAddress = clientAddress;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getClientAddress() {
        return this.clientAddress;
    }

    public String getServiceId() {
        return this.serviceId;
    }

    public int getNonce() {
        return nonce;
    }

    @Override
    public String toString() {
    return "RequestMessage{" +
            "clientId='" + clientId + '\'' +
            ", serviceId='" + serviceId + '\'' +
            ", nonce=" + nonce +
            '}';
    }
}
