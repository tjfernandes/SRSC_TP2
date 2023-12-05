package org.example.utils;

public class CommandReturn {
    private final String command;
    private final byte[] payload;

    public CommandReturn(String command, byte[] payload) {
        this.command = command;
        this.payload = payload;
    }

    public CommandReturn(String command) {
        this.command = command;
        this.payload = new byte[0];
    }


    public String getCommand() {
        return command;
    }

    public byte[] getPayload() {
        return payload;
    }
}
