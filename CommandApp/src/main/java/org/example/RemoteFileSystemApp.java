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

    public static final String[] CONFPROTOCOLS     = {"TLSv1.2"};;
    public static final String[] CONFCIPHERSUITES  = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_TYPE       = "JKS";
    public static final String KEYSTORE_PASSWORD   = "client_password";
    public static final String KEYSTORE_PATH       = "/keystore.jks";
    public static final String TRUSTSTORE_TYPE     = "JKS";
    public static final char[] TRUSTSTORE_PASSWORD = "client_truststore_password".toCharArray();
    public static final String TRUSTSTORE_PATH     = "/truststore.jks";
    public static final String TLS_VERSION         = "TLSv1.2";
    public static final String DISPATCHER_HOST     = "172.28.0.5";
    public static final int DISPATCHER_PORT        = 8080;

    public static void main(String[] args) throws IOException {
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

        // Read the server's response
        String response = reader.readLine();

        reader.close();
        writer.close();
        socket.close();

        return response;
    }

    private static SSLSocket initTLSSocket() {
        SSLSocket socket = null;
        try {

            KeyStore trustStore = KeyStore.getInstance(TRUSTSTORE_TYPE);
            trustStore.load(RemoteFileSystemApp.class.getResourceAsStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD);
            Enumeration<String> aliases = trustStore.aliases();

//            while (aliases.hasMoreElements()) {
//                String alias = aliases.nextElement();
//                Certificate certificate = trustStore.getCertificate(alias);
//                System.out.println("Alias: " + alias);
//                System.out.println("Certificate: " + certificate.toString());
//            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            System.out.println("HOST: " + DISPATCHER_HOST);
            System.out.println("PORT: " + DISPATCHER_PORT);

            socket = (SSLSocket) sslSocketFactory.createSocket("172.17.0.1", 8080);


            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            socket.startHandshake();

            SSLSession session = socket.getSession();

            System.out.println();
            System.out.println("Hum from my offer server decided to select\n");
            System.out.println("TLS protocol version: " + session.getProtocol());
            System.out.println("Ciphersuite: " + session.getCipherSuite());

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

}