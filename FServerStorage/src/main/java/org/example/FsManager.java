package org.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.drivers.DropboxDriver;
import org.example.drivers.LocalFileSystemDriver;

public class FsManager {


    private static final String ALGORITHM = "AES";
    private static final int KEYSIZE = 256;

    private CryptoStuff crypto;
    private LocalFileSystemDriver fs;
    private DropboxDriver dbx;
    private SecretKey key;

    private static final String FILESYSTEM_CONFIG_PATH = "/app/filesystem-config.properties";
    private static final String DROPBOXCONFIG_PATH = "/app/java/dropbox-config.properties";

    public FsManager() {
        crypto = CryptoStuff.getInstance();
        fs = new LocalFileSystemDriver(FILESYSTEM_CONFIG_PATH);
        //dbx = new DropboxDriver(DROPBOXCONFIG_PATH);
        try {
            Files.createDirectories(Paths.get("/filesystem"));

            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            this.key = kg.generateKey();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] lsCommand(String path) {
        List<String> fileList = fs.listFolder(path); 
        if(fileList == null) {
            return null;
        }
        String fileListString = String.join("\n", fileList);
        return fileListString.getBytes(StandardCharsets.UTF_8);
    }

    public boolean putCommand(String path, byte[] content) {
        byte[] encryptedContent;
    
        try {
            encryptedContent = crypto.encrypt(key, content);
        } catch (CryptoException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return false;
        }
    
        return fs.uploadFile(encryptedContent, path);
    }

    public byte[] getCommand(String path) {
        byte[] encryptedContent;
    
        encryptedContent = fs.downloadFile(path);
    
        if (encryptedContent == null) {
            return null;
        }

        byte[] decryptedContent;
    
        try {
            decryptedContent = crypto.decrypt(key, encryptedContent);
        } catch (CryptoException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    
        return decryptedContent;
    }

    public boolean mkdirCommand(String path) {
        return fs.createFolder(path);
    }

    public boolean rmCommand(String path) {
        return fs.deleteFile(path);
    }

    public boolean cpCommand(String sourcePath, String destinationPath) {
        return fs.copyFile(sourcePath, destinationPath);
    }
}
