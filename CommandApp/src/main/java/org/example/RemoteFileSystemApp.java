package org.example;


import java.awt.event.*;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class RemoteFileSystemApp {

    public static final String[] CONFPROTOCOLS     = {"TLSv1.2"};
    public static final String[] CONFCIPHERSUITES  = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_TYPE       = "JKS";
    public static final String KEYSTORE_PASSWORD   = "client_password";
    public static final String KEYSTORE_PATH       = "/keystore.jks";
    public static final String TRUSTSTORE_TYPE     = "JKS";
    public static final char[] TRUSTSTORE_PASSWORD = "client_truststore_password".toCharArray();
    public static final String TRUSTSTORE_PATH     = "/truststore.jks";
    public static final String TLS_VERSION         = "TLSv1.2";
    public static final String DISPATCHER_HOST     = "localhost";
    public static final int DISPATCHER_PORT        = 8080;

    public static void main(String[] args) throws IOException {
        System.setProperty("javax.net.debug", "ssl");
        try {
            // Sleep for 10 second (1000 milliseconds)
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        String response = requestCommand("login username password");
        System.out.println(response);
    }


    private static String requestCommand(String command) throws IOException {

        SSLSocket socket = initTLSSocket();

        // Communication logic with the server
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

        writer.write(command);
        writer.newLine();
        writer.flush();

        String response = "";
        // Read the server's response
        response = reader.readLine();
        System.out.println("response:" + response);

        return response;
    }

    private static SSLSocket initTLSSocket() {
        SSLSocket socket = null;
        try {

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(RemoteFileSystemApp.class.getResourceAsStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            System.out.println("HOST: " + DISPATCHER_HOST);
            System.out.println("PORT: " + DISPATCHER_PORT);

            socket = (SSLSocket) sslSocketFactory.createSocket(DISPATCHER_HOST, DISPATCHER_PORT);
            socket.setUseClientMode(true);
            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            socket.startHandshake();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

}