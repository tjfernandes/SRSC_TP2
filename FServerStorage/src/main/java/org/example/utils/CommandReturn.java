package org.example.utils;

public class CommandReturn implements java.io.Serializable {
    private final Command command;
    private final byte[] payload;

    public CommandReturn(Command command, byte[] payload) {
        this.command = command;
        this.payload = payload;
    }

    public CommandReturn(Command command) {
        this.command = command;
        this.payload = new byte[0];
    }

    public Command getCommand() {
        return command;
    }

    public byte[] getPayload() {
        return payload;
    }
}
