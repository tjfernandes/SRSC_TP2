package org.example.utils;

import java.time.LocalDateTime;

public class ResponseMessage {
    private final LocalDateTime issueTimeReturn;
    private final CommandReturn commandReturn;

    public ResponseMessage(CommandReturn commandReturn, LocalDateTime issueTimeReturn) {
        this.issueTimeReturn = LocalDateTime.now();
        this.commandReturn = commandReturn;
    }
    
    public CommandReturn getcommandReturn() {
        return commandReturn;
    }

    public LocalDateTime getissueTimeReturn() {
        return issueTimeReturn;
    }
}
