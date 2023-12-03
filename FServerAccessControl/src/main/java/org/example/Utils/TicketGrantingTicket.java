package org.example.Utils;

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;

public class TicketGrantingTicket implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String clientId;
    private final String clientAddress;
    private final String tgsServerIdentifier;
    private final String keyClientTGS;
    private final LocalDateTime issueTime;
    private final Duration lifetime;

    public TicketGrantingTicket(String clientId, String clientAddress, String tgsServerIdentifier, String keyClientTGS) {
        this.clientId = clientId;
        this.clientAddress = clientAddress;
        this.tgsServerIdentifier = tgsServerIdentifier;
        this.keyClientTGS = keyClientTGS;
        this.issueTime = LocalDateTime.now();
        this.lifetime = Duration.ofHours(8); // TGT validity period
    }

    public String getClientAddress() {
        return clientAddress;
    }

    public String getTgsServerIdentifier() {
        return tgsServerIdentifier;
    }

    public String getKey() {
        return keyClientTGS;
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
