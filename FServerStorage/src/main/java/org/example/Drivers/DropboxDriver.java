package org.example.Drivers;

import com.dropbox.core.DbxException;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.*;

import java.io.*;
import java.util.Properties;

public class DropboxDriver {
    private final String accessToken;
    private final String appKey;
    private final String appSecret;

    private final String appName;

    private final String basePath;

    public DropboxDriver(String configFilePath) {
        Properties properties = loadProperties(configFilePath);
        this.accessToken = properties.getProperty("ACCESS_TOKEN");
        this.appKey = properties.getProperty("APP_KEY");
        this.appSecret = properties.getProperty("APP_SECRET");
        this.appName = properties.getProperty("APP_NAME");
        this.basePath = properties.getProperty("LOCAL_BASE_PATH");
    }

    private Properties loadProperties(String configFilePath) {
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream(configFilePath)) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }

    public void uploadFile(byte[] content, String dropboxFilePath) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try (InputStream in = new ByteArrayInputStream(content)) {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            FileMetadata metadata = client.files()
                    .uploadBuilder(basePath + dropboxFilePath)
                    .withMode(WriteMode.ADD)
                    .uploadAndFinish(in);
            System.out.println("File uploaded to Dropbox: " + metadata.getPathDisplay());
        } catch (IOException | DbxException e) {
            e.printStackTrace();
        }
    }

    public void createFolder(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            Metadata metadata = client.files().createFolder(basePath+path);
            System.out.println("Folder created: " + metadata.getPathDisplay());
        } catch (DbxException e) {
            e.printStackTrace();
        }
    }

    public byte[] downloadFile(String dropboxFilePath) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            client.files().download(basePath + dropboxFilePath)
                    .download(outputStream);
            System.out.println("File downloaded from Dropbox: " + dropboxFilePath);
            return outputStream.toByteArray();
        } catch (IOException | DbxException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    public ListFolderResult listFolder(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            ListFolderResult result = client.files().listFolder(basePath+path);
            while (true) {
                for (Metadata metadata : result.getEntries()) {
                    System.out.println(metadata.getPathDisplay());
                }
                if (!result.getHasMore()) {
                    break;
                }
                result = client.files().listFolderContinue(result.getCursor());
            }
            return result;
        } catch (DbxException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void copyFile(String fromPath, String toPath) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            Metadata metadata = client.files().copyV2(basePath+fromPath, basePath+toPath).getMetadata();
            System.out.println("File copied to: " + metadata.getPathDisplay());
        } catch (DbxException e) {
            e.printStackTrace();
        }
    }

    public void deleteFile(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            Metadata metadata = client.files().deleteV2(basePath+path).getMetadata();
            System.out.println("File deleted: " + metadata.getPathDisplay());
        } catch (DbxException e) {
            e.printStackTrace();
        }
    }
}