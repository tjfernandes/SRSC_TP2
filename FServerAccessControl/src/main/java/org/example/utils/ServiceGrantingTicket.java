package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;

import javax.crypto.SecretKey;

public class ServiceGrantingTicket implements Serializable{

    @Serial
    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String clientAddress;
    private final String serverIdentifier;
    private final SecretKey keyClientServer;
    private final LocalDateTime issueTime;
    private final Duration lifetime;

    public ServiceGrantingTicket(String clientId, String clientAddress, String serverIdentifier, SecretKey keyClientServer) {
        this.clientId = clientId;
        this.clientAddress = clientAddress;
        this.serverIdentifier = serverIdentifier;
        this.keyClientServer = keyClientServer;
        this.issueTime = LocalDateTime.now();
        this.lifetime = Duration.ofMinutes(5); // TGT validity period
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public String getServerIdentifier() {
        return serverIdentifier;
    }

    public SecretKey getKey() {
        return keyClientServer;
    }

    public LocalDateTime getIssueTime() {
        return issueTime;
    }

    public boolean isValid() {
        return LocalDateTime.now().isBefore(issueTime.plus(lifetime));
    }

    public String getClientId() {
        return this.clientId;
    }

    
}
