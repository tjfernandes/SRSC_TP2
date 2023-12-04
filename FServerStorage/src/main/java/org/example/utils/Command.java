package org.example.utils;

public class Command {
    private final String command;
    private final byte[] payload;
    private final String path;
    private final String cpToPath;
    

    public Command(String command, byte[] payload, String path) {
        this.command = command;
        this.payload = payload;
        this.path = path;
        this.cpToPath = null;
    }

    public Command(String command, byte[] payload, String path, String cpToPath) {
        this.command = command;
        this.payload = payload;
        this.path = path;
        this.cpToPath = cpToPath;
    }

    public Command(String command, String path) {
        this.command = command;
        this.payload = new byte[0];
        this.path = path;
        this.cpToPath = null;
    }

    public String getCpToPath() {
        return cpToPath;
    }

    public String getCommand() {
        return command;
    }

    public byte[] getPayload() {
        return payload;
    }

    public String getPath() {
        return path;
    }

    public boolean isValid() {
        return !(path.contains("../") || (cpToPath != null && cpToPath.contains("../")));
    }
}
