package org.example;

import com.dropbox.core.DbxException;
import org.example.Crypto.CryptoException;
import org.example.Crypto.CryptoStuff;
import org.example.Crypto.Utils;
import org.example.Drivers.DropboxDriver;
import org.example.Drivers.LocalFileSystemDriver;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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

    public static void main(String[] args) throws DbxException {
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
        byte[] downloadedContent = fs.downloadFile(uploadTargetPath);

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
}