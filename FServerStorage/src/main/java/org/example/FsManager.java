package org.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.example.drivers.DropboxDriver;
import org.example.drivers.LocalFileSystemDriver;
import org.example.utils.Pair;

/*
 * FsManager is a class that manages the file system and the Dropbox driver.
 */
public class FsManager {

    private LocalFileSystemDriver fs;
    private DropboxDriver dbx;

    private static final String DROPBOXCONFIG_PATH = "/app/java/dropbox-config.properties";
    private static final String FILESYSTEM_PATH = "/filesystem";

    private static final String FULL_PATH_FORMAT_STRING = "%s/%s/%s";

    public FsManager() {
        fs = new LocalFileSystemDriver();
        // dbx = new DropboxDriver(DROPBOXCONFIG_PATH);

        try {
            Files.createDirectories(Paths.get("FILESYSTEM_PATH"));

            // Dummy client folder
            Files.createDirectories(Paths.get("FILESYSTEM_PATH" + "/client"));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getFullPath(String clientId, String path) {
        return String.format(FULL_PATH_FORMAT_STRING, FILESYSTEM_PATH, clientId, path);
    }

    public Pair<byte[], Integer> lsCommand(String clientId, String path) {
        Pair<List<String>, Integer> result = fs.listFolder(getFullPath(clientId, path));
        List<String> list = result.first;
        Integer errorCode = result.second;

        if (list != null) {
            byte[] fileArray = String.join("\n", list).getBytes(StandardCharsets.UTF_8);
            return new Pair<>(fileArray, errorCode);
        } else {
            return new Pair<>(null, errorCode);
        }
    }

    public int putCommand(String clientId, String path, byte[] content) {
        return fs.uploadFile(content, getFullPath(clientId, path));
    }

    public Pair<byte[], Integer> getCommand(String clientId, String path) {
        return fs.downloadFile(getFullPath(clientId, path));
    }

    public int mkdirCommand(String clientId, String path) {
        return fs.createFolder(getFullPath(clientId, path));
    }

    public int rmCommand(String clientId, String path) {
        return fs.deleteFile(getFullPath(clientId, path));
    }

    public int cpCommand(String clientId, String sourcePath, String destinationPath) {
        return fs.copyFile(getFullPath(clientId, sourcePath), getFullPath(clientId, destinationPath));
    }
}
