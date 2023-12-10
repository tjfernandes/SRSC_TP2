package org.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.example.drivers.DropboxDriver;
import org.example.drivers.LocalFileSystemDriver;
import org.example.utils.FileInfo;
import org.example.utils.FilePayload;
import org.example.utils.MessageStatus;
import org.example.utils.Pair;

/*
 * FsManager is a class that manages the file system and the Dropbox driver.
 */
public class FsManager {

    private LocalFileSystemDriver fs;
    private DropboxDriver dbx;

    private static final String DROPBOXCONFIG_PATH = "/app/dropbox-config.properties";
    private static final String FILESYSTEM_PATH = "/app/filesystem";
    private static final String FULL_PATH_FORMAT_STRING = "%s/%s/%s";
    private static final int BLOCK_SIZE_IN_BYTES = 4 * 1024;

    public FsManager() {
        fs = new LocalFileSystemDriver();
        dbx = new DropboxDriver(DROPBOXCONFIG_PATH);

        try {
            Files.createDirectories(Paths.get("filesystem"));

            // Dummy client folders on the local file system and on Dropbox
            Files.createDirectories(Paths.get("filesystem" + "/client"));
            dbx.deleteDirectory("client");
            dbx.createFolder("client");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Function to create a full path from a client id and a path
    private String createFullPath(String clientId, String path) {
        return String.format(FULL_PATH_FORMAT_STRING, FILESYSTEM_PATH, clientId, path);
    }

    // Function to create a path from a folder and a file name
    private String createPath(String path, String fileName) {
        return path + "/" + fileName;
    }

    // Function to list the files in a folder
    public Pair<byte[], Integer> lsCommand(String clientId, String path) {
        Pair<List<String>, Integer> result = fs.listFolder(createFullPath(clientId, path));
        List<String> list = result.first;
        Integer status = result.second;

        if (list != null) {
            byte[] fileArray = String.join("\n", list).getBytes(StandardCharsets.UTF_8);
            return new Pair<>(fileArray, status);
        } else {
            return new Pair<>(new byte[0], status);
        }
    }

    // Function to put a file into the file system
    public int putCommand(String clientId, String path, FilePayload content) {
        byte[] metadata = content.getMetaData();
        byte[] fileContent = content.getFileContent();

        int numBlocks = (int) Math.ceil((double) fileContent.length / BLOCK_SIZE_IN_BYTES);
        LinkedList<UUID> blockOrder = new LinkedList<>();
        UUID metadataUuid = UUID.randomUUID();
        String blockPath = createPath(clientId, metadataUuid.toString());
        dbx.uploadFile(metadata, blockPath);

        for (int i = 0; i < numBlocks; i++) {
            int startIndex = i * BLOCK_SIZE_IN_BYTES;
            int endIndex = Math.min(startIndex + BLOCK_SIZE_IN_BYTES, fileContent.length);
            byte[] block = Arrays.copyOfRange(fileContent, startIndex, endIndex);

            UUID uuid = UUID.randomUUID();
            blockOrder.add(uuid);

            blockPath = createPath(clientId, uuid.toString());
            dbx.uploadFile(block, blockPath);
        }

        FileInfo fileInfo = new FileInfo(metadataUuid, blockOrder);

        byte[] fileInfoBytes;
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(fileInfo);
            fileInfoBytes = bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }

        fs.uploadFile(fileInfoBytes, createFullPath(clientId, path));

        return MessageStatus.OK_NO_CONTENT.getCode();
    }

    // Function to get a file from the file system
    public Pair<byte[], Integer> getCommand(String clientId, String path) {
        byte[] fileInfoBytes;
        FileInfo fileInfo;
        try {
            fileInfoBytes = Files.readAllBytes(Paths.get(createFullPath(clientId, path)));
            try (ByteArrayInputStream bis = new ByteArrayInputStream(fileInfoBytes);
                    ObjectInputStream ois = new ObjectInputStream(bis)) {
                fileInfo = (FileInfo) ois.readObject();
            } catch (ClassNotFoundException e) {
                System.out.println(e.getMessage());
                return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
            return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }

        // Get the file chunks and concatenate them
        List<UUID> blockOrder = fileInfo.getChunks();
        byte[] fileContent = new byte[blockOrder.size() * BLOCK_SIZE_IN_BYTES];
        for (int i = 0; i < blockOrder.size(); i++) {
            UUID uuid = blockOrder.get(i);
            String blockPath = createPath(clientId, path);
            Pair<byte[], Integer> blockPair = fs.downloadFile(blockPath);
            if (blockPair.second != MessageStatus.OK.getCode()) {
                return new Pair<>(new byte[0], blockPair.second);
            }
            byte[] block = blockPair.first;
            System.arraycopy(block, 0, fileContent, i * BLOCK_SIZE_IN_BYTES, block.length);
        }

        return new Pair<>(fileContent, MessageStatus.OK.getCode());
    }

    // Function to make a directory in the file system
    public int mkdirCommand(String clientId, String path) {
        return fs.createFolder(createFullPath(clientId, path));
    }

    // Function to delete a file from the file system
    public int rmCommand(String clientId, String path) {
        String fullPath = createFullPath(clientId, path);
        byte[] fileInfoBytes;
        FileInfo fileInfo;
        try {
            fileInfoBytes = Files.readAllBytes(Paths.get(fullPath));
            try (ByteArrayInputStream bis = new ByteArrayInputStream(fileInfoBytes);
                    ObjectInputStream ois = new ObjectInputStream(bis)) {
                fileInfo = (FileInfo) ois.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
                return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return MessageStatus.INTERNAL_SERVER_ERROR.getCode();
        }

        // Delete the file chunks
        List<UUID> blockOrder = fileInfo.getChunks();
        for (UUID uuid : blockOrder) {
            String blockPath = createPath(clientId, uuid.toString());
            int result = dbx.deleteFile(blockPath);
            if (result != MessageStatus.OK_NO_CONTENT.getCode()) {
                return result;
            }
        }

        // Delete the file metadata
        UUID id = fileInfo.getHeader();
        String blockPath = createPath(clientId, id.toString());
        dbx.deleteFile(blockPath);

        return fs.deleteFile(fullPath);
    }

    // Function to copy a file from the file system
    public int cpCommand(String clientId, String sourcePath, String destinationPath) {
        return fs.copyFile(createFullPath(clientId, sourcePath), createFullPath(clientId, destinationPath));
    }

    // Function to get a file from the file system
    public Pair<byte[], Integer> fileCommand(String clientId, String path) {
        byte[] fileInfoBytes;
        FileInfo fileInfo;
        try {
            fileInfoBytes = Files.readAllBytes(Paths.get(createFullPath(clientId, path)));
            try (ByteArrayInputStream bis = new ByteArrayInputStream(fileInfoBytes);
                    ObjectInputStream ois = new ObjectInputStream(bis)) {
                fileInfo = (FileInfo) ois.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
                return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
            }
        } catch (IOException e) {
            e.printStackTrace();
            return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }

        // Get the file Metadata
        UUID uuid = fileInfo.getHeader();
        String blockPath = createPath(clientId, uuid.toString());
        Pair<byte[], Integer> blockPair = dbx.downloadFile(blockPath);
        if (blockPair.second != MessageStatus.OK.getCode()) {
            return new Pair<>(new byte[0], blockPair.second);
        }
        return new Pair<>(blockPair.first, MessageStatus.OK.getCode());
    }
}
