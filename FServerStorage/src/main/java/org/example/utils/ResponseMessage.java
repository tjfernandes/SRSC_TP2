package org.example.utils;

import java.time.LocalDateTime;

public class ResponseMessage {
    private final LocalDateTime issueTime;

    public ResponseMessage() {
        this.issueTime = LocalDateTime.now();
    }

    public LocalDateTime getIssueTime() {
        return issueTime;
    }
}
