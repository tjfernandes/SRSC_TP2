package org.example.Drivers;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class LocalFileSystemDriver {
    private final String basePath;

    public LocalFileSystemDriver(String configFilePath) {
        Properties properties = loadProperties(configFilePath);
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

    public void uploadFile(byte[] fileContent, String targetFilePath) {
        try (ByteArrayInputStream in = new ByteArrayInputStream(fileContent);
             FileOutputStream out = new FileOutputStream(basePath + targetFilePath)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            System.out.println("File uploaded: " + targetFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void createFolder(String path) {
        Path folderPath = Path.of(basePath + path);
        try {
            Files.createDirectories(folderPath);
            System.out.println("Folder created: " + folderPath.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] downloadFile(String filePath) {
        Path sourcePath = Path.of(basePath + filePath);
        try {
            return Files.readAllBytes(sourcePath);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public List<String> listFolder(String path) {
        List<String> fileList = new ArrayList<>();
        Path folderPath = Path.of(basePath + path);
        try {
            Files.walk(folderPath)
                    .filter(Files::isRegularFile)
                    .forEach(file -> fileList.add(file.toString()));
            return fileList;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void copyFile(String fromPath, String toPath) {
        Path sourcePath = Path.of(basePath + fromPath);
        Path targetPath = Path.of(basePath + toPath);
        try {
            Files.copy(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("File copied to: " + targetPath.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void deleteFile(String path) {
        Path filePath = Path.of(basePath + path);
        try {
            Files.deleteIfExists(filePath);
            System.out.println("File deleted: " + filePath.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
