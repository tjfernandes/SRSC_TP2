package org.example.utils;

import java.time.LocalDateTime;

public class Authenticator {
    private final String userId;
    private final String userAddress;
    private final LocalDateTime timestamp;

    public Authenticator(String userId, String userAddress, LocalDateTime timestamp) {
        this.userId = userId;
        this.userAddress = userAddress;
        this.timestamp = timestamp;
    }

    public String getUserId() {
        return userId;
    }

    public String getUserAddress() {
        return userAddress;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}
