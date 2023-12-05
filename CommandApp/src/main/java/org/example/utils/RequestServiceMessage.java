package org.example.utils;

import java.io.Serializable;

public class RequestServiceMessage implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] Encryptedsgt;
    private final byte[] authenticator;

    public RequestServiceMessage(byte[] Encryptedsgt, byte[] authenticator) {
        this.Encryptedsgt = Encryptedsgt;
        this.authenticator = authenticator;
    }

    public byte[] getEncryptedSgt() {
        return Encryptedsgt;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
}