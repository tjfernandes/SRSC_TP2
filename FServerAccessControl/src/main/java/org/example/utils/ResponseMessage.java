package org.example.utils;

import java.io.Serializable;
import java.time.LocalDateTime;

import javax.crypto.SecretKey;

public class ResponseMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] authenticator;
    private final String serviceId;
    private final LocalDateTime timestamp;
    private final SecretKey sessionKey;
    private final ServiceGrantingTicket sgt;

    public ResponseMessage(byte[] authenticator, String serviceId, LocalDateTime timestamp, SecretKey sessionKey, ServiceGrantingTicket sgt) {
        this.authenticator = authenticator;
        this.serviceId = serviceId;
        this.timestamp = timestamp;
        this.sessionKey = sessionKey;
        this.sgt = sgt;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }

    public String getServiceId() {
        return serviceId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public ServiceGrantingTicket getSgt() {
        return sgt;
    }
}