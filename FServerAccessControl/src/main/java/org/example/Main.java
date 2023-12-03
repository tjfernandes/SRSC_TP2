package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.example.utils.RequestMessage;
import org.example.utils.ResponseMessage;
import org.example.utils.ServiceGrantingTicket;
import org.example.utils.TicketGrantingTicket;

import java.security.cert.Certificate;

public class Main {

    public static final String[] CONFPROTOCOLS = { "TLSv1.2" };;
    public static final String[] CONFCIPHERSUITES = { "TLS_RSA_WITH_AES_256_CBC_SHA256" };
    public static final String KEYSTORE_PASSWORD = "access_control_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "access_control_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8082;

    public static final String ALGORITHM = "AES";
    public static final int KEYSIZE = 256;

    private static String tgsKey;
    private static String storageKey;

    private static SSLServerSocket serverSocket;

    public static void main(String[] args) {
        System.out.println("Hello world!");

        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream("keys.properties")) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        tgsKey = props.getProperty("TGS_KEY");
        storageKey = props.getProperty("STORAGE_KEY");

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

            RequestMessage requestMessage;

            while ((requestMessage = (RequestMessage) objectInputStream.readObject()) != null) {
                System.out.println("Received message: " + requestMessage);

                String serviceId = requestMessage.getServiceId();
                TicketGrantingTicket tgt = requestMessage.getTgt();
                byte[] authenticator = requestMessage.getAuthenticator();

                KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
                kg.init(KEYSIZE);
                SecretKey generatedkey = kg.generateKey();

                ServiceGrantingTicket sgt = new ServiceGrantingTicket(tgt.getClientId(), tgt.getClientAddress(),
                        serviceId, generatedkey);

                ResponseMessage responseMessage = new ResponseMessage(generatedkey, serviceId, sgt.getIssueTime(), sgt);
                objectOutputStream.writeObject(responseMessage);
                objectOutputStream.flush();

                objectOutputStream.close();
                objectInputStream.close();
                requestSocket.close();

            }
        } catch (IOException | NoSuchAlgorithmException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /*
     * private static void handleRequest1(SSLSocket clientSocket, SSLServerSocket
     * serverSocket) {
     * try {
     * // Communication logic with the client
     * BufferedReader reader = new BufferedReader(new
     * InputStreamReader(clientSocket.getInputStream()));
     * BufferedWriter writer = new BufferedWriter(new
     * OutputStreamWriter(clientSocket.getOutputStream()));
     * 
     * String message;
     * while ((message = reader.readLine()) != null) {
     * System.out.println("Received message: " + message);
     * 
     * // Example response
     * writer.write("Server received your message: " + message);
     * writer.newLine();
     * writer.flush();
     * }
     * 
     * writer.close();
     * reader.close();
     * clientSocket.close();
     * serverSocket.close();
     * } catch (IOException e) {
     * e.printStackTrace();
     * }
     * }
     */

}