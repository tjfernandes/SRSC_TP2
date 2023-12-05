package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;

public class Authenticator implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private final String clientId;
    private final String clientAddress;
    private final LocalDateTime timestamp;

    public Authenticator(String clientId, String clientAddress) {
        this.clientId = clientId;
        this.clientAddress = clientAddress;
        timestamp = LocalDateTime.now();
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}


