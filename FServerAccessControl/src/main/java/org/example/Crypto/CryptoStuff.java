package org.example.Crypto;


import java.security.Key;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;


import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;

public class CryptoStuff {

    private static CryptoStuff instance;

    private static final byte[] ivBytes  = new byte[]
     {
	      0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
        0x0f, 0x0d, 0x0e, 0x0c
     };

    private static GCMParameterSpec gcmParameterSpec;

    private CryptoStuff() {
      gcmParameterSpec = new GCMParameterSpec(128, ivBytes);
    }

    public static CryptoStuff getInstance() {
        if (instance == null) {
            instance = new CryptoStuff();
        }
        return instance;
    }

    public static byte[] encrypt(Key key, byte[] inputBytes) throws CryptoException, InvalidAlgorithmParameterException {
        return doCrypto(Cipher.ENCRYPT_MODE, key, inputBytes);
    }

    public static byte[] decrypt(Key key, byte[] inputBytes) throws CryptoException, InvalidAlgorithmParameterException {
        return doCrypto(Cipher.DECRYPT_MODE, key, inputBytes);
    }

    private static byte[]  doCrypto(int cipherMode, Key key, byte[] inputBytes)
            throws CryptoException, InvalidAlgorithmParameterException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            
            cipher.init(cipherMode, key, gcmParameterSpec);

            return cipher.doFinal(inputBytes);

        } catch ( BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new CryptoException("Error encrypting/decrypting data" + ex.getMessage());
        }
    }

    private byte[] generateRandomIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12]; // 96 bits IV for AES-GCM
        secureRandom.nextBytes(iv);
        return iv;
    }
}
