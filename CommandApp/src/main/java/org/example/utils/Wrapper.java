package org.example.utils;

import java.util.UUID;

public class Wrapper implements java.io.Serializable {

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

    @Override
    public String toString() {
        return "Wrapper{" +
                "messageType=" + messageType +
                ", messageId=" + messageId +
                '}';
    }
}
