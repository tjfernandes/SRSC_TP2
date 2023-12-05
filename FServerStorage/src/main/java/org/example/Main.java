package org.example;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Properties;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.utils.Authenticator;
import org.example.utils.Command;
import org.example.utils.CommandReturn;
import org.example.utils.RequestMessage;
import org.example.utils.ResponseMessage;
import org.example.utils.ServiceGrantingTicket;
import org.example.utils.Wrapper;

public class Main {

    public static final String[] CONFPROTOCOLS = { "TLSv1.2" };;
    public static final String[] CONFCIPHERSUITES = { "TLS_RSA_WITH_AES_256_CBC_SHA256" };
    public static final String KEYSTORE_PASSWORD = "storage_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "storage_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8080;
    public static final int MY_PORT = 8083;
    public static final String STORAGE_TGS_KEY_PATH = "/app/crypto-config.properties";

    public static final String ALGORITHM = "AES";
    public static final int KEYSIZE = 256;

    enum CommandEnum {
        GET, PUT, RM, LS, MKDIR, CP
    }

    public static void main(String[] args) {
        final SSLServerSocket serverSocket = server();
        FsManager fsManager = new FsManager();
        CryptoStuff crypto = CryptoStuff.getInstance();

        // loading the key from the properties file
        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(STORAGE_TGS_KEY_PATH)) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // converting from String to SecretKey
        SecretKey key = convertStringToSecretKeyto(props.getProperty("STORAGE_TGS_KEY"));

        System.out.println("Server started on port " + MY_PORT);
        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(
                        () -> handleRequest(clientSocket, serverSocket, fsManager, crypto, key));
                clientThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static SecretKey convertStringToSecretKeyto(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return originalKey;
    }

    public static CommandReturn processCommand(Command command, FsManager fsManager, CommandEnum commandEnum) {
        byte[] payload = null;
        boolean ok = false;

        switch (commandEnum) {
            case GET:
                payload = fsManager.getCommand(command.getPath());
                break;
            case PUT:
                ok = fsManager.putCommand(command.getPath(), command.getPayload());
                break;
            case RM:
                ok = fsManager.rmCommand(command.getPath());
                break;
            case LS:
                payload = fsManager.lsCommand(command.getPath());
                break;
            case MKDIR:
                ok = fsManager.mkdirCommand(command.getPath());
                break;
            case CP:
                ok = fsManager.cpCommand(command.getPath(), command.getCpToPath());
                break;
        }

        if (ok)
            return new CommandReturn(command.getCommand(), 200);
        else if (payload != null)
            return new CommandReturn(command.getCommand(), payload, 200);
        else
            return new CommandReturn(command.getCommand(), 400);
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket, FsManager fsManager,
            CryptoStuff crypto, SecretKey key) {
        try {
            // Creating the streams
            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            // Reading the RequestMessage
            Wrapper wrapper = (Wrapper) objectInputStream.readObject();
            RequestMessage requestMessage = (RequestMessage) deserialize(wrapper.getMessage());
            byte messageType = wrapper.getMessageType();
            UUID messageId = wrapper.getMessageId();

            // Processing the RequestMessage
            ResponseMessage response = processRequest(requestMessage, fsManager, crypto, key);

            byte[] encryptedResponse = crypto.encrypt(key, serialize(response));

            // Create a new Wrapper object with the byte array
            Wrapper responseWrapper = new Wrapper(messageType, encryptedResponse, messageId);

            // Sending the ResponseMessage
            objectOutputStream.writeObject(responseWrapper);
            objectOutputStream.flush();

            // // Closing the streams
            // objectOutputStream.close();
            // objectInputStream.close();
            // requestSocket.close();

        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | CryptoException e) {
            e.printStackTrace();
        }
    }

    private static ResponseMessage processRequest(RequestMessage requestMessage, FsManager fsManager,
            CryptoStuff crypto, SecretKey key)
            throws IOException, ClassNotFoundException, InvalidAlgorithmParameterException, CryptoException {

        // Decrypting the Service Granting Ticket
        byte[] encryptedsgt = requestMessage.getEncryptedSgt();
        byte[] sgtBytes = crypto.decrypt(key, encryptedsgt);
        ServiceGrantingTicket sgt = (ServiceGrantingTicket) deserialize(sgtBytes);

        // Decrypting the Authenticator
        byte[] encryptedAuth = requestMessage.getAuthenticator();
        byte[] authBytes = crypto.decrypt(key, encryptedAuth);
        Authenticator authenticator = (Authenticator) deserialize(authBytes);

        LocalDateTime returnTime = authenticator.getTimestamp().plusHours(1);

        // Checking if the Authenticator is valid
        if (!authenticator.isValid(sgt.getClientId(), sgt.getClientAddress())) {
            return new ResponseMessage(new CommandReturn(requestMessage.getCommand().getCommand(), 403), returnTime);
        }

        Command command = requestMessage.getCommand();

        // Checking if the command is valid
        if (!command.isValid()) {
            return new ResponseMessage(new CommandReturn(requestMessage.getCommand().getCommand(), 403), returnTime);
        }

        CommandReturn commandReturn = processCommand(command, fsManager, CommandEnum.valueOf(command.getCommand()));

        return new ResponseMessage(commandReturn, returnTime);
    }

    private static SSLServerSocket server() {

        try {
            // KeyStore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
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
