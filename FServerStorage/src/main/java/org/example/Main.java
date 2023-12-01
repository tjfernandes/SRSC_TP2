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

    public static void main(String[] args) {
        try {
            // Load your keystore and truststore here;
            KeyStore ks = KeyStore.getInstance("JKS");
            try (InputStream is = Main.class.getResourceAsStream("/storage-keystore.jks")) {
                ks.load(is, "your_storage_keystore_password".toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "your_storage_keystore_password".toCharArray());

            // SSLContext
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(kmf.getKeyManagers(), null, null);

            SSLServerSocketFactory sslServerSocketFactory = sc.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(8084);

            System.out.println("Server is listening on port 8083...");

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
