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
    public static final int PORT_2_DISPATCHER       = 8083;

    public void lsCommand() {

    }

    public void putCommand() {

    }

    public void getCommand() {

    }

    public void mkdirCommand() {

    }

    public void rmCommand() {

    }

    public void cpCommand() {

    }
/*
    public void test() {
        String cryptoConfigFilePath = "src/main/java/crypto-config.properties";
        String inputFilePath = "src/main/java/ola.txt";
        String uploadTargetPath = "ola.txt";

        // Create an instance of CryptoStuff
        CryptoStuff crypto = null;
        try {
            crypto = new CryptoStuff(cryptoConfigFilePath);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        // Read the file content as a byte array
        byte[] fileContent;
        try {
            fileContent = Files.readAllBytes(Paths.get(inputFilePath));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        // Encrypt the file content
        byte[] encryptedContent;
        try {
            encryptedContent = crypto.encrypt(fileContent);
        } catch (CryptoException e) {
            e.printStackTrace();
            return;
        }

        // Now, you can upload the encrypted content
        LocalFileSystemDriver fs = new LocalFileSystemDriver("src/main/java/filesystem-config.properties");
        fs.uploadFile(Utils.toHex(encryptedContent).getBytes(), uploadTargetPath);

        // Download the file content as a byte array
        //byte[] downloadedContent = fs.downloadFile(uploadTargetPath);

        // Decrypt the downloaded content
        byte[] decryptedContent;
        try {
            decryptedContent = crypto.decrypt(encryptedContent);
        } catch (CryptoException e) {
            e.printStackTrace();
            return;
        }

        // Convert decrypted content to hex byte array
        byte[] decryptedHexByteArray = Utils.bytesToHexByteArray(decryptedContent);

        // Print the decrypted content as hex byte array
        System.out.println("Decrypted (Hex Byte Array): " + Utils.toHex(decryptedHexByteArray));

    }
 */
    public static void main(String[] args) {
       initTLSSocket();
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
