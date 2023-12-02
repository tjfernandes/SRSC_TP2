package org.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class Main {

    private static final String[] confciphersuites = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    private static final String[] confprotocols = {"TLSv1.2"};

    public static void main(String[] args) {
        final SSLServerSocket serverSocket = server();
        while (true) {
            try(SSLSocket requestSocket = (SSLSocket) serverSocket.accept()) {
                System.out.println("Client connected");
                handleRequest(requestSocket, serverSocket);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static SSLServerSocket server() {
        try {
            char[] keyStorePassword = "authentication_password".toCharArray();
            char[] keyPassword = "authentication_password".toCharArray();

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("/app/keystore.jks"), keyStorePassword);

            System.out.println("keystore size:" + ks.size());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keyPassword);
            
            // SSLContext
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(8083);
            serverSocket.setEnabledProtocols(confprotocols);
	        serverSocket.setEnabledCipherSuites(confciphersuites);   
            
            return serverSocket;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket) {
        try {
            // Communication logic with the request
            BufferedReader reader = new BufferedReader(new InputStreamReader(requestSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(requestSocket.getOutputStream()));

            String message;
            while ((message = reader.readLine()) != null) {
                System.out.println("Received message: " + message);

                // Example response
                writer.write("Server received your message: " + message);
                writer.newLine();
                writer.flush();
            }

            writer.close();
            reader.close();
            requestSocket.close();
            serverSocket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}