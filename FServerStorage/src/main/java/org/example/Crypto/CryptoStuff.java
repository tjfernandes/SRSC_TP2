package org.example.Crypto;

import java.io.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;


/**
 * A utility class that encrypts or decrypts a file.
 **/
public class CryptoStuff {
    private static CryptoStuff instance;

    // security.conf fields
    public static final String ALGORITHM = "ALGORITHM";
    public static final String CONFIDENTIALITY = "CONFIDENTIALITY";
    public static final String CONFIDENTIALITY_KEY = "CONFIDENTIALITY-KEY";

    public static final String DIGEST = "DIGEST";

    public static final String IV = "IV";

    private final String algorithm;
    private final String confidentiality;
    private final String confidentialityKey;
    private final String iv;

    private final MessageDigest digest;

    public CryptoStuff(String configFilePath) throws NoSuchAlgorithmException {
        Properties properties = loadProperties(configFilePath);
        confidentiality = properties.getProperty(CONFIDENTIALITY);
        confidentialityKey = properties.getProperty(CONFIDENTIALITY_KEY);
        algorithm = confidentiality.split("/")[0];
        iv = properties.getProperty(IV);
        digest = MessageDigest.getInstance(properties.getProperty(DIGEST));
    }

    private Properties loadProperties(String configFilePath) {
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream(configFilePath)) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }

    public byte[] encrypt(byte[] inputBytes) throws CryptoException {
        byte[] keyBytes = Utils.hexStringToByteArray(confidentialityKey);
        return doCrypto(Cipher.ENCRYPT_MODE, keyBytes, inputBytes);
    }

    public byte[] decrypt(byte[] inputBytes) throws CryptoException {
        byte[] keyBytes = Utils.hexStringToByteArray(confidentialityKey);
        return doCrypto(Cipher.DECRYPT_MODE, keyBytes, inputBytes);
    }

    public String hashString(String input) {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        return Utils.toHex(hashBytes(inputBytes));
    }

    public byte[] hashBytes(byte[] inputBytes) {
        return digest.digest(inputBytes);
    }

    private byte[] doCrypto(int cipherMode, byte[] key, byte[] inputFile) throws CryptoException {
        try {
            Key secretKey = new SecretKeySpec(key, algorithm);
            String[] tokens = confidentiality.split("/");
            Cipher cipher = Cipher.getInstance(confidentiality);
            if (tokens[0].equals("RC4"))
                cipher.init(cipherMode, secretKey);
            else {
                AlgorithmParameterSpec ivSpec;
                if (tokens[0].equals("ChaCha20"))
                    ivSpec = new ChaCha20ParameterSpec(Utils.hexStringToByteArray(iv), 1);
                else if (tokens.length > 1 && tokens[1].equals("GCM"))
                    ivSpec = new GCMParameterSpec(128, iv.getBytes());
                else
                    ivSpec = new IvParameterSpec(iv.getBytes());

                cipher.init(cipherMode, secretKey, ivSpec);
            }

            return cipher.doFinal(inputFile);
        } catch (InvalidKeyException | BadPaddingException
                 | IllegalBlockSizeException
                 | InvalidAlgorithmParameterException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}