package org.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Enumeration;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.security.cert.Certificate;

public class Main {

    public static final String[] CONFPROTOCOLS      = {"TLSv1.2"};;
    public static final String[] CONFCIPHERSUITES   = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_PASSWORD    = "access_control_password";
    public static final String KEYSTORE_PATH        = "/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD  = "access_control_truststore_password";
    public static final String TRUSTSTORE_PATH      = "/truststore.jks";
    public static final String TLS_VERSION          = "TLSv1.2";
    public static final int PORT_2_DISPATCHER       = 8085;
    public static void main(String[] args) {
       initTLSSocket();
    }

    private static void initTLSSocket(){

        try {
            //Keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            InputStream keystoreStream = Main.class.getResourceAsStream(KEYSTORE_PATH);
            ks.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            //TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream trustStoreStream = Main.class.getResourceAsStream(TRUSTSTORE_PATH);
            trustStore.load(trustStoreStream, TRUSTSTORE_PASSWORD.toCharArray());
            Enumeration<String> aliases = trustStore.aliases();

            //Print all certificates in truststore
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = trustStore.getCertificate(alias);
                System.out.println("Alias: " + alias);
                System.out.println("Certificate: " + certificate.toString());
            }
            
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);
            
            // SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(PORT_2_DISPATCHER);
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
	        serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

            System.out.println("Server is listening on socket...");
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            handleRequest(clientSocket, serverSocket);   
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleRequest(SSLSocket clientSocket, SSLServerSocket serverSocket) {
        try {
            // Communication logic with the client
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

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
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}   