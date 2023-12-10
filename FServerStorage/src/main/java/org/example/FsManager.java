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

            // Dummy clients folders on the local file system and on Dropbox
            Files.createDirectories(Paths.get("filesystem" + "/client"));
            Files.createDirectories(Paths.get("filesystem" + "/alice"));
            dbx.deleteDirectory("client");
            dbx.createFolder("client");
            dbx.deleteDirectory("alice");
            dbx.createFolder("alice");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Function to create a full path from a client id and a path
    private String createFullPath(String clientId, String path) {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        return String.format(FULL_PATH_FORMAT_STRING, FILESYSTEM_PATH, clientId, path);
    }

    private String createPath(String path, String fileName) {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
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

        saveFileInfo(fileInfo, createFullPath(clientId, path));

        return MessageStatus.OK_NO_CONTENT.getCode();
    }

    // Function to get a file from the file system
    public Pair<byte[], Integer> getCommand(String clientId, String path) {
        String fullPath = createFullPath(clientId, path);
        FileInfo fileInfo = retrieveFileInfo(fullPath);

        if (fileInfo == null) {
            return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
        }

        // Get the file chunks and concatenate them
        List<UUID> blockOrder = fileInfo.getChunks();
        ByteArrayOutputStream fileContentStream = new ByteArrayOutputStream();
        for (UUID uuid : blockOrder) {
            String blockPath = createPath(clientId, uuid.toString());
            Pair<byte[], Integer> blockPair = dbx.downloadFile(blockPath);
            if (blockPair.second != MessageStatus.OK.getCode()) {
                return new Pair<>(new byte[0], blockPair.second);
            }
            byte[] block = blockPair.first;
            try {
                fileContentStream.write(block);
            } catch (IOException e) {
                e.printStackTrace();
                return new Pair<>(new byte[0], MessageStatus.INTERNAL_SERVER_ERROR.getCode());
            }
        }
        byte[] fileContent = fileContentStream.toByteArray();
        return new Pair<>(fileContent, MessageStatus.OK.getCode());
    }

    // Function to make a directory in the file system
    public int mkdirCommand(String clientId, String path) {
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return fs.createFolder(createFullPath(clientId, path));
    }

    // Function to delete a file from the file system
    public int rmCommand(String clientId, String path) {
        String fullPath = createFullPath(clientId, path);
        FileInfo fileInfo = retrieveFileInfo(fullPath);

        if (fileInfo == null) {
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
        String fullSourcePath = createFullPath(clientId, sourcePath);
        String fullDestinationPath = createFullPath(clientId, destinationPath);
        FileInfo sourceFileInfo = retrieveFileInfo(fullSourcePath);

        LinkedList<UUID> newBlockOrder = new LinkedList<>();

        // For each block in the source file, create a new block with the same data but
        // a new UUID
        for (UUID oldUuid : sourceFileInfo.getChunks()) {
            String oldBlockPath = createPath(clientId, oldUuid.toString());
            Pair<byte[], Integer> oldBlockPair = dbx.downloadFile(oldBlockPath);

            if (oldBlockPair.second != MessageStatus.OK.getCode()) {
                return oldBlockPair.second;
            }

            byte[] oldBlock = oldBlockPair.first;

            // Create a new UUID, save it in newBlockOrder, and upload a file to Dropbox
            // with the same content but the new UUID as the filename
            UUID newUuid = UUID.randomUUID();
            newBlockOrder.add(newUuid);
            String newBlockPath = createPath(clientId, newUuid.toString());
            dbx.uploadFile(oldBlock, newBlockPath);
        }

        // Do the same for the metadata
        UUID newMetadataUuid = UUID.randomUUID();
        String oldBlockPath = createPath(clientId, sourceFileInfo.getHeader().toString());
        Pair<byte[], Integer> oldBlockPair = dbx.downloadFile(oldBlockPath);
        if (oldBlockPair.second != MessageStatus.OK.getCode()) {
            return oldBlockPair.second;
        }
        byte[] oldBlock = oldBlockPair.first;
        String newBlockPath = createPath(clientId, newMetadataUuid.toString());
        dbx.uploadFile(oldBlock, newBlockPath);

        FileInfo newFileInfo = new FileInfo(newMetadataUuid, newBlockOrder);

        // Save the new FileInfo object to the destination file
        saveFileInfo(newFileInfo, fullDestinationPath);

        return MessageStatus.OK_NO_CONTENT.getCode();
    }

    // Function to get a file from the file system
    public Pair<byte[], Integer> fileCommand(String clientId, String path) {
        String fullPath = createFullPath(clientId, path);
        FileInfo fileInfo = retrieveFileInfo(fullPath);

        if (fileInfo == null) {
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

    private FileInfo retrieveFileInfo(String filePath) {
        FileInfo fileInfo = null;
        try {
            byte[] fileInfoBytes = Files.readAllBytes(Paths.get(filePath));
            try (ByteArrayInputStream bis = new ByteArrayInputStream(fileInfoBytes);
                    ObjectInputStream ois = new ObjectInputStream(bis)) {
                fileInfo = (FileInfo) ois.readObject();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return fileInfo;
    }

    private void saveFileInfo(FileInfo fileInfo, String filePath) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(fileInfo);
            oos.flush();
            byte[] fileInfoBytes = bos.toByteArray();

            Files.write(Paths.get(filePath), fileInfoBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
