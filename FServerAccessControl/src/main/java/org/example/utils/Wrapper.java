package org.example.utils;

import java.util.UUID;

public class Wrapper {

    private final byte messageType;
    private final byte[] message;
    private final UUID messageId;

    public Wrapper(byte messageType, byte[] message, UUID messageId) {
        this.messageType = messageType;
        this.message = message;
        this.messageId = messageId;
    }

    public byte getMessageType() {
        return messageType;
    }

    public byte[] getMessage() {
        return message;
    }

    public UUID getMessageId() {
        return messageId;
    }
}
