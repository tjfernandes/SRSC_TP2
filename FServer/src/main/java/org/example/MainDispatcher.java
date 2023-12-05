package org.example;

import javax.net.ssl.*;

import org.example.utils.Wrapper;

import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class MainDispatcher {

    public enum ModuleName {
        STORAGE,
        AUTHENTICATION,
        ACCESS_CONTROL
    }

    public static final String[] CONFPROTOCOLS = { "TLSv1.2" };;
    public static final String[] CONFCIPHERSUITES = { "TLS_RSA_WITH_AES_256_CBC_SHA256" };
    public static final String KEYSTORE_PASSWORD = "dispatcher_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "dispatcher_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int MY_PORT = 8080;

    private static String[] getHostAndPort(ModuleName moduleName) {
        switch (moduleName) {
            case STORAGE:
                return new String[] { "172.17.0.1", "8083" };
            case AUTHENTICATION:
                return new String[] { "172.17.0.1", "8081" };
            case ACCESS_CONTROL:
                return new String[] { "172.17.0.1", "8082" };
            default:
                throw new IllegalArgumentException("Invalid module name");
        }
    }

    // A map from request IDs to client sockets
    private static Map<UUID, SSLSocket> clientSocketMap = new HashMap<>();

    public static void main(String[] args) throws Exception {

        // Create a new thread to the client
        new Thread(() -> initTLSServerSocket()).start();
        System.out.println("Server started on port " + MY_PORT);
    }

    private static void initTLSServerSocket() {
        try {
            //Keystore
            System.out.println("Loading keystore...");
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // TrustStore
            System.out.println("Loading truststore...");
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
    
            // SSLContext
            System.out.println("Setting up SSL context...");
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MY_PORT);
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
            serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                System.out.println("New connection accepted");
                ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
                Wrapper message = (Wrapper) objectInputStream.readObject();
                System.out.println(message);
                new Thread(() -> clientHandleRequest(message, socket)).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void clientHandleRequest(Wrapper request, SSLSocket clientSocket) {
        try {
            // Add the client socket to the map
            clientSocketMap.put(request.getMessageId(), clientSocket);

            SSLSocket socket = initTLSClientSocket(chooseModule(request));

            // Forward the request to the correct socket
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(request);
            objectOutputStream.flush();

            // Get the response from the correct socket
            ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
            Wrapper response = (Wrapper) objectInputStream.readObject();

            // Handle the response
            new Thread(() -> handleResponse(response)).start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static ModuleName chooseModule(Wrapper request) {
        byte type = request.getMessageType();

        // Choose the correct socket based on the message type
        return switch (type) {
            case 1 -> ModuleName.AUTHENTICATION;
            case 3 -> ModuleName.ACCESS_CONTROL;
            case 6 -> ModuleName.STORAGE;
            default -> {
                System.out.println("Invalid message type: " + type);
                yield null;
            }
        };
    }

    private static void handleResponse(Wrapper response) {
        try {
            // Get the client socket for this response
            SSLSocket clientSocket = clientSocketMap.get(response.getMessageId());
            if (clientSocket == null) {
                // Handle the case where there's no client socket for this response
                System.out.println("No client socket for response: " + response);
                return;
            }

            // Send the response back to the client
            ObjectOutputStream clientOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            clientOutputStream.writeObject(response);
            clientOutputStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SSLSocket initTLSClientSocket(ModuleName module) {
        SSLSocket socket = null;
        try {
            String[] hostAndPort = getHostAndPort(module);
    
            //KeyStore
            System.out.println("Loading keystore...");
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());
    
            //TrustStore
            System.out.println("Loading truststore...");
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            System.out.println("Setting up SSL context...");
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Set up the socket to use TLSv1.2
            System.out.println("Setting up socket...");
            socket = (SSLSocket) sslSocketFactory.createSocket(hostAndPort[0], Integer.parseInt(hostAndPort[1]));
            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            // Start the handshake
            System.out.println("Starting handshake...");
            socket.startHandshake();

            return socket;
    
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | KeyManagementException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

}