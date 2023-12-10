package org.example.messages;

import java.time.LocalDateTime;

import org.example.utils.CommandReturn;

public class ResponseServiceMessage implements java.io.Serializable {
    private final LocalDateTime issueTimeReturn;
    private final CommandReturn commandReturn;

    public ResponseServiceMessage(CommandReturn commandReturn, LocalDateTime issueTimeReturn) {
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
