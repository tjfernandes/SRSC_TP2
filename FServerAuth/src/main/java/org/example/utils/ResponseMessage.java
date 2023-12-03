package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.time.Duration;
import java.time.LocalDateTime;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;

public class ResponseMessage implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final byte[] generatedKey;
    private final String serviceId;
    private final LocalDateTime issueTime;
    private final Duration lifetime;
    private byte[] encryptedTGT;

    public ResponseMessage(byte[] generatedKey, String serviceId, byte[] encryptedTGT) {
        this.generatedKey = generatedKey;
        this.serviceId = serviceId;
        this.issueTime = LocalDateTime.now();
        this.lifetime = Duration.ofHours(8);
        this.encryptedTGT = null;
        try {
            this.encryptedTGT = CryptoStuff.getInstance().encrypt(generatedKey, encryptedTGT);
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Error encrypting TGT: Invalid algorithm parameter");
        } catch (CryptoException e) {
            System.out.println("Error encrypting TGT: Invalid algorithm parameter");
        }
    }

    public String getServiceId() {
        return this.serviceId;
    }

    public LocalDateTime getIssueTime() {
        return issueTime;
    }

    public byte[] getGeneratedKey() {
        return generatedKey;
    }

    public Duration getLifetime() {
        return lifetime;
    }

    public byte[] getEncryptedTGT() {
        return encryptedTGT;
    }
}
