package org.example.utils;

public class Wrapper {

    private final byte messageType;
    private final Object object;
    
    public Wrapper(byte messageType, Object object) {
        this.messageType = messageType;
        this.object = object;
    }

    public byte getMessageType() {
        return messageType;
    }

    public Object getObject() {
        return object;
    }
}
