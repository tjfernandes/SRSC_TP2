package org.example.utils;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.time.LocalDateTime;

public class ResponseTGTMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String serviceId;
    private final LocalDateTime timestamp;
    private final SecretKey sessionKey;
    private final byte[] sgt;

    public ResponseTGTMessage(SecretKey sessionKey, String serviceId, LocalDateTime timestamp, byte[] sgt) {
        this.serviceId = serviceId;
        this.timestamp = timestamp;
        this.sessionKey = sessionKey;
        this.sgt = sgt;
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

    public byte[] getSgt() {
        return sgt;
    }
}