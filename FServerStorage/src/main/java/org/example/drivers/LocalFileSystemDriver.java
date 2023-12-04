package org.example.drivers;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;

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

    public boolean uploadFile(byte[] fileContent, String targetFilePath) {
    try {
        Path path = Paths.get(basePath + targetFilePath);
        Files.createDirectories(path.getParent());

        try (ByteArrayInputStream in = new ByteArrayInputStream(fileContent);
             FileOutputStream out = new FileOutputStream(path.toString())) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            return false;
        }
    } catch (IOException e) {
        return false;
    }
    return true;
}


    public boolean createFolder(String path) {
        Path folderPath = Path.of(basePath + path);
        try {
            Files.createDirectories(folderPath);
            System.out.println("Folder created: " + folderPath.toString());
        } catch (IOException e) {
          return false;
        }
        return true;
    }

    public byte[] downloadFile(String filePath) {
        try {
            Path sourcePath = Path.of(basePath + filePath);
            return Files.readAllBytes(sourcePath);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public List<String> listFolder(String path) {
        List<String> fileList = new ArrayList<>();
        Path folderPath = Path.of(basePath + path);
        try (Stream<Path> paths = Files.list(folderPath)) {
            paths.forEach(p -> {
                String fileName = p.getFileName().toString();
                if (Files.isDirectory(p)) {
                    fileList.add(fileName + " (Directory)");
                } else {
                    fileList.add(fileName);
                }
            });
            return fileList;
        } catch (IOException e) {
            return null;
        }
    }

    public boolean copyFile(String fromPath, String toPath) {
        
        try {
            Path sourcePath = Path.of(basePath + fromPath);
            Path targetPath = Path.of(basePath + toPath);
            Files.copy(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("File copied to: " + targetPath.toString());
        } catch (IOException e) {
            return false;
        }

        return true;
    }

    public boolean deleteFile(String path) {
        try {
            Path filePath = Path.of(basePath + path);
            Files.deleteIfExists(filePath);
        } catch (IOException e) {
            return false;
        }
        return true;
    }
}
