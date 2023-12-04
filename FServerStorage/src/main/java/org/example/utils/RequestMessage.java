package org.example.utils;

import java.io.Serializable;

public class RequestMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] Encryptedsgt;
    private final byte[] authenticator;
    private final Command command;

    public RequestMessage(byte[] Encryptedsgt, byte[] authenticator,Command command) {
        this.Encryptedsgt = Encryptedsgt;
        this.authenticator = authenticator;
        this.command = command;
    }

    public Command getCommand() {
        return command;
    }

    public byte[] getEncryptedSgt() {
        return Encryptedsgt;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}