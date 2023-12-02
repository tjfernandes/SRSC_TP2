package org.example;

import org.example.Crypto.CryptoException;
import org.example.Crypto.CryptoStuff;
import org.example.Crypto.Utils;
import org.example.Drivers.LocalFileSystemDriver;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.*;

public class Main {

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

    private static final String SIG_SCHEME_STR =
            "rsa_pkcs1_sha256,rsa_pss_rsae_sha256,rsa_pss_pss_sha256," +
                    "ed448,ed25519,ecdsa_secp256r1_sha256";
 */
    public static void main(String[] args) {
System.out.println("CONASSA");        /*System.setProperty("jdk.tls.client.SignatureSchemes", SIG_SCHEME_STR);
        System.setProperty("jdk.tls.server.SignatureSchemes", SIG_SCHEME_STR);
*/
        String[] confciphersuites={"TLS_RSA_WITH_AES_256_CBC_SHA256"};
        String[] confprotocols={"TLSv1.2"};

        try {
            // Load your keystore and truststore here;
            char[] keyStorePassword = "storage_password".toCharArray();
            char[] keyPassword = "storage_password".toCharArray();

            KeyStore ks = KeyStore.getInstance("JKS");

            try (InputStream is = Main.class.getResourceAsStream("/keystore.jks")) {
                System.out.println("apanhou");
                ks.load(is, keyStorePassword);
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, keyPassword);

            /* 
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream is = Main.class.getResourceAsStream("/trustedstore")) {
                System.out.println("ENCONTROU TRUSTSTORE");
                trustStore.load(is, "your_client_truststore_password".toCharArray());
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
*/
            // SSLContext
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, null);
System.out.println("Server is listening on port 8084...");
            SSLServerSocketFactory sslServerSocketFactory = sc.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(8084);
System.out.println("Server is listening on port 8084...");
            serverSocket.setEnabledProtocols(confprotocols);
	        serverSocket.setEnabledCipherSuites(confciphersuites);

            System.out.println("Server is listening on port 8084...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();

                // Handle client communication in a separate thread
                new Thread(() -> handleClient(clientSocket, serverSocket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(SSLSocket clientSocket, SSLServerSocket serverSocket) {
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
