package org.example.utils;

import java.time.LocalDateTime;

public class ResponseMessage {
    private final LocalDateTime issueTime;
    private final byte[] payload;
    private final int status;

    public ResponseMessage(byte[] payload, int status) {
        this.issueTime = LocalDateTime.now();
        this.payload = payload;
        this.status = status;
    }

    public ResponseMessage(int status) {
        this.issueTime = LocalDateTime.now();
        this.payload = new byte[0];
        this.status = status;
    }

    public byte[] getPayload() {
        return payload;
    }

    public int getStatus() {
        return status;
    }

    public LocalDateTime getIssueTime() {
        return issueTime;
    }
}
