package org.example.utils;

import org.example.crypto.CryptoStuff;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.UUID;

public class Login {

    private static final String HASHING_ALGORITHMS = "PBKDF2WithHmacSHA256";
    private static final String CLIENT_PASS = "12345";

    private static final String TGS_ID = "access_control";
    private static final String CLIENT_ADDR = "127.0.0.1";
    private static final String SERVICE_ID = "storage";
    private static final byte[] salt = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,0x0f, 0x0d, 0x0e, 0x0c, 0x07, 0x06, 0x05, 0x04};;


    public static void sendAuthRequest(SSLSocket socket, String clientId) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestAuthenticationMessage requestMessage = new RequestAuthenticationMessage(clientId, CLIENT_ADDR, TGS_ID);

            byte[] requestMessageSerialized = serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void sendTGSRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestTGSMessage requestMessage = new RequestTGSMessage(SERVICE_ID, encryptedTGT, encryptedAuthenticator);

            byte[] requestMessageSerialized = serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void sendServiceRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator) {
//        Req requestServiceMessage = null;
//        try {
//            // Communication logic with the server
//            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
//
//
//
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

    public static ResponseAuthenticationMessage processAuthResponse(SSLSocket socket, String password) {
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {
            System.out.println("ENTRA processAUthResponse");
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            byte[] encryptedResponse = wrapper.getMessage();

            SecretKey clientKey = CryptoStuff.getInstance().convertByteArrayToSecretKey(hashPassword(password));
            byte[] descryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);

            responseAuthenticationMessage = (ResponseAuthenticationMessage) deserialize(descryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseAuthenticationMessage;
    }

    public static ResponseTGSMessage processTGSResponse(SSLSocket socket, SecretKey key) {
        ResponseTGSMessage responseTGSMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();

            byte[] encryptedResponse = wrapper.getMessage();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);

            responseTGSMessage = (ResponseTGSMessage) deserialize(decryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseTGSMessage;
    }



    private static byte[] serialize(Object object) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(object);
            objectOutputStream.flush();
            return byteArrayOutputStream.toByteArray();
        }
    }

    private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
             ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {
            return objectInputStream.readObject();
        }
    }

    private static byte[] hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        int keyLength = 256;

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASHING_ALGORITHMS);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        System.out.println("Hashed password: " + Base64.getEncoder().encodeToString(hash));
        return hash;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
