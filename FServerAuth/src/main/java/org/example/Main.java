package org.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.utils.RequestAuthenticationMessage;
import org.example.utils.ResponseAuthenticationMessage;
import org.example.utils.TicketGrantingTicket;
import org.example.utils.Wrapper;

public class Main {

    public static final String[] CONFPROTOCOLS = {"TLSv1.2"};
    ;
    public static final String[] CONFCIPHERSUITES = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_PASSWORD = "authentication_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "authentication_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8080;
    public static final int MY_PORT = 8081;

    public static final String ALGORITHM = "AES";
    public static final int KEYSIZE = 256;

    public static final String TGS_KEY_PATH = "/app/crypto-config.properties";
    public static final String TGS_KEY = "TGS_AS_KEY";


    public static void main(String[] args) {
        Authentication authentication = new Authentication();
        //TODO - inserir client para test
        authentication.register("client", "12345");

        final SSLServerSocket serverSocket = server();
        System.out.println("Server started on port " + MY_PORT);

        // Load the Properties file
        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(TGS_KEY_PATH)) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket, serverSocket, authentication, props));
                clientThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket, Authentication authentication, Properties props) {
        try {

            System.out.println("ENTRA");
            // Create input and output streams for the socket
            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            // Read the message from the client
            Wrapper wrapper = (Wrapper) objectInputStream.readObject();
            RequestAuthenticationMessage requestAuthenticationMessage = (RequestAuthenticationMessage) deserialize(wrapper.getMessage());
            byte messageType = wrapper.getMessageType();
            UUID uuid = wrapper.getMessageId();

            // Generate a key for client/tgs communication
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            SecretKey generatedkey = kg.generateKey();

            // Create a TGT
            TicketGrantingTicket tgt = new TicketGrantingTicket(requestAuthenticationMessage.getClientId(), requestAuthenticationMessage.getClientAddress(), requestAuthenticationMessage.getServiceId(), generatedkey);
            byte[] tgtBytes = serialize(tgt);

            // Key to encrypt TGT
            String keyTGT = props.getProperty(TGS_KEY);
            System.out.println("keyTGT: " + keyTGT);
            SecretKey secretKeyTGT = CryptoStuff.getInstance().convertStringToSecretKeyto(keyTGT);

            // Key to encrypt response
            String key = authentication.getUsernamePassword(requestAuthenticationMessage.getClientId());
            System.out.println("KEY STRING: " + key);
            SecretKey secretKey = CryptoStuff.getInstance().convertStringToSecretKeyto(key);

            // Encrypt TGT and send it to the client
            byte[] encryptedTGT = CryptoStuff.getInstance().encrypt(secretKeyTGT, tgtBytes);
            byte[] responseBytes = serialize(new ResponseAuthenticationMessage(generatedkey, encryptedTGT));
            objectOutputStream.writeObject(new Wrapper(messageType, CryptoStuff.getInstance().encrypt(secretKey, responseBytes), uuid));
            objectOutputStream.flush();

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | CryptoException |
                 InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }


    private static SSLServerSocket server() {

        try {
            //KeyStore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            //TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MY_PORT);
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
            serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

            return serverSocket;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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
}