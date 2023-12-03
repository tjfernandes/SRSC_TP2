package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.example.Crypto.CryptoException;
import org.example.Crypto.CryptoStuff;

public class ResponseMessage implements Serializable {
    
    @Serial
    private static final long serialVersionUID = 1L;

    private final SecretKey generatedKey;
    private final LocalDateTime issueTime;
    private final Duration lifetime;
    private byte[] encryptedTGT;

    public ResponseMessage(SecretKey generatedKey, byte[] encryptedTGT) {
        this.generatedKey = generatedKey;
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

    public LocalDateTime getIssueTime() {
        return issueTime;
    }

    public SecretKey getGeneratedKey() {
        return generatedKey;
    }

    public Duration getLifetime() {
        return lifetime;
    }

    public byte[] getEncryptedTGT() {
        return encryptedTGT;
    }

    @Override
    public String toString() {
    return "ResponseMessage{" +
        "generatedKey=" + generatedKey +
        ", issueTime=" + issueTime +
        ", lifetime=" + lifetime +
        ", encryptedTGT=" + Arrays.toString(encryptedTGT) +
        '}';
    }
}
