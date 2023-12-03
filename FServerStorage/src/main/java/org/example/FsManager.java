package org.example;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.example.Crypto.CryptoException;
import org.example.Crypto.CryptoStuff;
import org.example.Drivers.DropboxDriver;
import org.example.Drivers.LocalFileSystemDriver;

public class FsManager {


    private static final String ALGORITHM = "AES";
    private static final int KEYSIZE = 256;

    private CryptoStuff crypto;
    private LocalFileSystemDriver fs;
    private DropboxDriver dbx;
    private SecretKey key;

    private static final String FILESYSTEM_CONFIG_PATH = "src/main/java/filesystem-config.properties";
    private static final String DROPBOXCONFIG_PATH = "src/main/java/dropbox-config.properties";

    public FsManager() {
        crypto = CryptoStuff.getInstance();
        fs = new LocalFileSystemDriver(FILESYSTEM_CONFIG_PATH);
        dbx = new DropboxDriver(DROPBOXCONFIG_PATH);
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            this.key = kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public List<String> lsCommand(String path) {
        return fs.listFolder(path);
    }

    public void putCommand(String path, byte[] content) {
        byte[] encryptedContent;
    
        try {
            encryptedContent = crypto.encrypt(key, content);
        } catch (CryptoException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return;
        }
    
        fs.uploadFile(encryptedContent, path);
    }

    public byte[] getCommand(String path) {
        byte[] encryptedContent;
    
        encryptedContent = fs.downloadFile(path);
    
        byte[] decryptedContent;
    
        try {
            decryptedContent = crypto.decrypt(key, encryptedContent);
        } catch (CryptoException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    
        return decryptedContent;
    }

    public void mkdirCommand(String path) {
        fs.createFolder(path);
    }

    public void rmCommand(String path) {
        fs.deleteFile(path);
    }

    public void cpCommand(String sourcePath, String destinationPath) {
        fs.copyFile(sourcePath, destinationPath);
    }
}
