package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Properties;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.example.Crypto.CryptoException;
import org.example.Crypto.CryptoStuff;
import org.example.utils.Authenticator;
import org.example.utils.RequestTGSMessage;
import org.example.utils.ResponseTGSMessage;
import org.example.utils.ServiceGrantingTicket;
import org.example.utils.TicketGrantingTicket;
import org.example.utils.Wrapper;

import java.security.cert.Certificate;
import java.time.LocalDateTime;

public class Main {

    public static final String[] CONFPROTOCOLS = { "TLSv1.2" };;
    public static final String[] CONFCIPHERSUITES = { "TLS_RSA_WITH_AES_256_CBC_SHA256" };
    public static final String KEYSTORE_PASSWORD = "access_control_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "access_control_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8082;
    private static final String KEYS_PATH = "/app/keys.properties";

    private static final String ALGORITHM = "AES";
    private static final int KEYSIZE = 256;

    private static SecretKey tgsKey;
    private static SecretKey storageKey;

    private static SSLServerSocket serverSocket;

    public static void main(String[] args) {
        System.out.println("Hello world!");

        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(KEYS_PATH)) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // converting from String to SecretKey
        tgsKey = convertStringToSecretKeyto(props.getProperty("TGS_KEY"));
        storageKey = convertStringToSecretKeyto(props.getProperty("STORAGE_KEY"));

        initTLSSocket();

        while (true) {
            System.out.println("Server is listening on socket...");
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket, serverSocket));
                clientThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    private static void initTLSSocket() {

        try {
            // Keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            Enumeration<String> aliases = trustStore.aliases();

            // Print all certificates in truststore
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = trustStore.getCertificate(alias);
                System.out.println("Alias: " + alias);
                System.out.println("Certificate: " + certificate.toString());
            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            serverSocket = (SSLServerSocket) sslServerSocketFactory
                    .createServerSocket(PORT_2_DISPATCHER);
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
            serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket) {
        try {
            // Communication logic with the request
            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());
            Wrapper wrapper = (Wrapper) objectInputStream.readObject();
            System.out.println("Received message: " + wrapper);

            // deserialize request message
            RequestTGSMessage requestTGSMessage = (RequestTGSMessage) deserializeObject(wrapper.getMessage());

            String serviceId = requestTGSMessage.getServiceId();
            byte[] tgtSerialized = requestTGSMessage.getTgt();
            byte[] authenticatorSerialized = requestTGSMessage.getAuthenticator();

            // deserialize authenticator
            Authenticator authenticator = (Authenticator) deserializeObject(authenticatorSerialized);

            // decrypt and deserialize TGT
            CryptoStuff.getInstance();
            tgtSerialized = CryptoStuff.getInstance().decrypt(tgsKey, tgtSerialized);
            TicketGrantingTicket tgt = (TicketGrantingTicket) deserializeObject(tgtSerialized);
            SecretKey keyClientTGS = convertStringToSecretKeyto(tgt.getKey());

            // check if authenticator is valid
            if (!authenticator.isValid(tgt.getClientId(), tgt.getClientAddress())) {
                System.out.println("Authenticator is not valid");
                return;
            }

            // generate key for ticket
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            SecretKey generatedkey = kg.generateKey();

            // create ticket
            ServiceGrantingTicket sgt = new ServiceGrantingTicket(tgt.getClientId(), tgt.getClientAddress(), serviceId,
                    generatedkey);
            LocalDateTime issueTime = sgt.getIssueTime();

            // serialize the ticket and encrypt it
            byte[] sgtSerialized = serializeObject(sgt);
            sgtSerialized = CryptoStuff.getInstance().encrypt(storageKey, sgtSerialized);

            // serialize and encrypt message
            byte[] msgSerialized = serializeObject(
                    new ResponseTGSMessage(keyClientTGS, serviceId, issueTime, sgtSerialized));
            msgSerialized = CryptoStuff.getInstance().encrypt(keyClientTGS, msgSerialized);

            // create wrapper message
            Wrapper wrapperMessage = new Wrapper((byte) 4, msgSerialized, UUID.randomUUID());

            // send wrapper message
            objectOutputStream.writeObject(wrapperMessage);
            objectOutputStream.flush();

            // closing streams/sockets
            objectOutputStream.close();
            objectInputStream.close();
            requestSocket.close();

        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidAlgorithmParameterException
                | CryptoException e) {
            e.printStackTrace();
        }
    }

    private static SecretKey convertStringToSecretKeyto(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    private static byte[] serializeObject(Object object) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(object);
            byte[] serializedObject = bos.toByteArray();
            return serializedObject;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Object deserializeObject(byte[] serializedObject) {
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(serializedObject);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object object = ois.readObject();
            return object;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

}