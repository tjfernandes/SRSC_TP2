package org.example.utils;

public class Wrapper {

    private final byte messageType;
    private final byte[] message;
    
    public Wrapper(byte messageType, byte[] message) {
        this.messageType = messageType;
        this.message = message;
    }

    public byte getMessageType() {
        return messageType;
    }

    public byte[] getMessage() {
        return message;
    }
}
