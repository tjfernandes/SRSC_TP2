package org.example.utils;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class User implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final String HASHING_ALGORITHMS = "SHA-256";

    private String username;
    private String hashedPassword;
    private byte[] salt;


    public User(String username, String password) throws NoSuchAlgorithmException {
        this.username = username;
        this.salt = generateSalt();
        this.hashedPassword = hashPassword(password);
    }

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHMS);
        md.update(salt);
        byte[] bytes = md.digest(password.getBytes());
        return bytesToHex(bytes);
    }

    public String getUsername() {
        return username;
    }

    public String getHashedPassword() {
        return hashedPassword;
    }

    public byte[] getSalt() {
        return salt;
    }
}