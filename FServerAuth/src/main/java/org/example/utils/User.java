package org.example.utils;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class User implements Serializable {
    private static final long serialVersionUID = 1L;

    private static final String HASHING_ALGORITHMS = "SHA-256";
    private static final byte[] salt = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,0x0f, 0x0d, 0x0e, 0x0c, 0x07, 0x06, 0x05, 0x04};

    private String username;
    private String hashedPassword;


    public User(String username, String password) throws NoSuchAlgorithmException {
        this.username = username;
        this.hashedPassword = hashPassword(password);
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