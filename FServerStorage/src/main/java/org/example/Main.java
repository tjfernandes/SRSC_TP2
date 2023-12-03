package org.example;

import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.security.cert.Certificate;
import javax.net.ssl.*;

public class Main {

    public static final String[] CONFPROTOCOLS      = {"TLSv1.2"};;
    public static final String[] CONFCIPHERSUITES   = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_PASSWORD    = "storage_password";
    public static final String KEYSTORE_PATH        = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD  = "storage_truststore_password";
    public static final String TRUSTSTORE_PATH      = "/app/truststore.jks";
    public static final String TLS_VERSION          = "TLSv1.2";
    public static final int PORT_2_DISPATCHER       = 8080;
    public static final int MY_PORT                 = 8083;

    /* 
    public static void test() {
        String inputFilePath = "/app/ola.txt";
        
        byte[] fileContent;
    
        try {
            fileContent = Files.readAllBytes(Paths.get(inputFilePath));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        FsManager fsManager = new FsManager();
        fsManager.putCommand("ola.txt", fileContent);
        byte[] a = fsManager.getCommand("ola.txt");

        System.out.println("File content: " + new String(a));    
    }
  */
    public static void main(String[] args) {
       initTLSSocket();
       //test();
    }

    private static void initTLSSocket(){

        try {
            //Keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            //TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
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
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MY_PORT);
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
	        serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

            System.out.println("Server is listening...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket, serverSocket));
                clientThread.start();
            }
            
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
                writer.write("Server Storage received your message: " + message);
                writer.newLine();
                writer.flush();
            }

            writer.close();
            reader.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
