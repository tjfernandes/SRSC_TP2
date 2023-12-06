package org.example.utils;

public class CommandReturn implements java.io.Serializable {
    private final String command;
    private final byte[] payload;
    private final int status;

    public CommandReturn(String command, byte[] payload, int status) {
        this.command = command;
        this.payload = payload;
        this.status = status;
    }

    public CommandReturn(String command, int status) {
        this.command = command;
        this.payload = new byte[0];
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public String getCommand() {
        return command;
    }

    public byte[] getPayload() {
        return payload;
    }
}
