package org.example.drivers;

import com.dropbox.core.DbxException;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.*;

import java.io.*;
import java.util.Properties;
import java.util.logging.Level;

import org.example.StorageService;
import org.example.utils.MessageStatus;
import org.example.utils.Pair;

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

    public Pair<FileMetadata, Integer> uploadFile(byte[] content, String dropboxFilePath) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try (InputStream in = new ByteArrayInputStream(content)) {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            FileMetadata metadata = client.files()
                    .uploadBuilder(basePath + dropboxFilePath)
                    .withMode(WriteMode.ADD)
                    .uploadAndFinish(in);
            StorageService.logger.log(Level.INFO, "File uploaded to Dropbox: " + dropboxFilePath);
            return new Pair<>(metadata, MessageStatus.OK_NO_CONTENT.getCode());
        } catch (UploadErrorException e) {
            if (e.errorValue.isPath()) {
                return new Pair<>(null, MessageStatus.CONFLICT.getCode());
            } else {
                e.printStackTrace();
                return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
            }
        } catch (IOException | DbxException e) {
            e.printStackTrace();
            return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }
    }

    public int createFolder(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            CreateFolderResult result = client.files().createFolderV2(basePath + path);
            Metadata metadata = result.getMetadata();
            StorageService.logger.log(Level.INFO, "Folder created on Dropbox: " + metadata.getPathDisplay());
            return MessageStatus.OK_NO_CONTENT.getCode();
        } catch (CreateFolderErrorException e) {
            if (e.errorValue.isPath() && e.errorValue.getPathValue().isConflict()) {
                StorageService.logger.log(Level.INFO, "Folder already exists on Dropbox: " + path);
                return MessageStatus.CONFLICT.getCode();
            } else {
                e.printStackTrace();
                return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
            }
        } catch (DbxException e) {
            e.printStackTrace();
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
    }

    public Pair<byte[], Integer> downloadFile(String dropboxFilePath) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            client.files().download(basePath + dropboxFilePath)
                    .download(outputStream);
            StorageService.logger.log(Level.INFO, "File downloaded from Dropbox: " + dropboxFilePath);
            return new Pair<>(outputStream.toByteArray(), MessageStatus.OK.getCode());
        } catch (DownloadErrorException e) {
            if (e.errorValue.isPath() && e.errorValue.getPathValue().isNotFound()) {
                StorageService.logger.log(Level.INFO, "File not found on Dropbox: " + dropboxFilePath);
                return new Pair<>(new byte[0], MessageStatus.NOT_FOUND.getCode());
            } else {
                e.printStackTrace();
                return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
            }
        } catch (IOException | DbxException e) {
            e.printStackTrace();
            return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }
    }

    public Pair<ListFolderResult, Integer> listFolder(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            ListFolderResult result = client.files().listFolder(basePath + path);
            while (true) {
                for (Metadata metadata : result.getEntries()) {
                    System.out.println(metadata.getPathDisplay());
                }
                if (!result.getHasMore()) {
                    break;
                }
                result = client.files().listFolderContinue(result.getCursor());
            }
            return new Pair<>(result, MessageStatus.OK.getCode());
        } catch (ListFolderErrorException e) {
            if (e.errorValue.isPath() && e.errorValue.getPathValue().isNotFound()) {
                StorageService.logger.log(Level.INFO, "Folder not found on Dropbox: " + path);
                return new Pair<>(null, MessageStatus.NOT_FOUND.getCode());
            } else {
                e.printStackTrace();
                return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
            }
        } catch (DbxException e) {
            e.printStackTrace();
            return new Pair<>(null, MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }
    }

    public int copyFile(String fromPath, String toPath) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            Metadata metadata = client.files().copyV2(basePath + fromPath, basePath + toPath).getMetadata();
            StorageService.logger.log(Level.INFO, "File copied on Dropbox: " + metadata.getPathDisplay());
            return MessageStatus.OK_NO_CONTENT.getCode();
        } catch (RelocationErrorException e) {
            if (e.errorValue.isFromLookup() && e.errorValue.getFromLookupValue().isNotFound()) {
                StorageService.logger.log(Level.INFO, "Source file not found on Dropbox: " + fromPath);
                return MessageStatus.NOT_FOUND.getCode();
            } else if (e.errorValue.isTo() && e.errorValue.getToValue().isConflict()) {
                StorageService.logger.log(Level.INFO, "Destination file already exists on Dropbox: " + toPath);
                return MessageStatus.CONFLICT.getCode();
            } else {
                e.printStackTrace();
                return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
            }
        } catch (DbxException e) {
            e.printStackTrace();
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
    }

    public int deleteFile(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            Metadata metadata = client.files().deleteV2(basePath + path).getMetadata();
            System.out.println("File deleted: " + metadata.getPathDisplay());
            return MessageStatus.OK_NO_CONTENT.getCode();
        } catch (DeleteErrorException e) {
            if (e.errorValue.isPathLookup() && e.errorValue.getPathLookupValue().isNotFound()) {
                return MessageStatus.NOT_FOUND.getCode();
            } else {
                e.printStackTrace();
                return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
            }
        } catch (DbxException e) {
            e.printStackTrace();
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
    }

    public int deleteDirectory(String path) {
        DbxRequestConfig config = DbxRequestConfig.newBuilder(appName).build();
        try {
            DbxClientV2 client = new DbxClientV2(config, accessToken);
            Metadata metadata = client.files().deleteV2(basePath + path).getMetadata();
            System.out.println("Directory deleted: " + metadata.getPathDisplay());
            return MessageStatus.OK_NO_CONTENT.getCode();
        } catch (DeleteErrorException e) {
            if (e.errorValue.isPathLookup() && e.errorValue.getPathLookupValue().isNotFound()) {
                return MessageStatus.NOT_FOUND.getCode();
            } else {
                e.printStackTrace();
                return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
            }
        } catch (DbxException e) {
            e.printStackTrace();
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }
    }
}