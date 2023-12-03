package org.example.Utils;

import java.io.Serial;
import java.time.Duration;
import java.time.LocalDateTime;

public class ServiceGrantingTicket {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String clientAddress;
    private final String serverIdentifier;
    private final String keyClientServer;
    private final LocalDateTime issueTime;
    private final Duration lifetime;

    public ServiceGrantingTicket(String clientId, String clientAddress, String serverIdentifier, String keyClientServer) {
        this.clientId = clientId;
        this.clientAddress = clientAddress;
        this.serverIdentifier = serverIdentifier;
        this.keyClientServer = keyClientServer;
        this.issueTime = LocalDateTime.now();
        this.lifetime = Duration.ofHours(8); // TGT validity period
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public String getServerIdentifier() {
        return serverIdentifier;
    }

    public String getKey() {
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
