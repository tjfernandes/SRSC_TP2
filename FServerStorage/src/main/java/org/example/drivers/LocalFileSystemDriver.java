package org.example.drivers;

import java.io.*;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.example.utils.Pair;

public class LocalFileSystemDriver {

    public LocalFileSystemDriver() {
    }

    public int uploadFile(byte[] fileContent, String targetFilePath) {
        try {
            Path path = Paths.get(targetFilePath);
            Files.createDirectories(path.getParent());

            try (ByteArrayInputStream in = new ByteArrayInputStream(fileContent);
                    FileOutputStream out = new FileOutputStream(path.toString())) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                return 500;
            }
        } catch (IOException e) {
            return 500;
        }
        return 204;
    }

    public int createFolder(String path) {
        Path folderPath = Path.of(path);
        try {
            Files.createDirectories(folderPath);
            return 204;
        } catch (FileAlreadyExistsException e) {
            return 409;
        } catch (IOException e) {
            return 500;
        }
    }

    public Pair<byte[], Integer> downloadFile(String filePath) {
        try {
            Path sourcePath = Path.of(filePath);
            return new Pair<>(Files.readAllBytes(sourcePath), 0);
        } catch (NoSuchFileException e) {
            return new Pair<>(null, 404);
        } catch (IOException e) {
            return new Pair<>(null, 500);
        }
    }

    public Pair<List<String>, Integer> listFolder(String path) {
        List<String> fileList = new ArrayList<>();
        Path folderPath = Path.of(path);
        try (Stream<Path> paths = Files.list(folderPath)) {
            paths.forEach(p -> {
                String fileName = p.getFileName().toString();
                if (Files.isDirectory(p)) {
                    fileList.add(fileName + " (Directory)");
                } else {
                    fileList.add(fileName);
                }
            });

            return new Pair<>(fileList, fileList.size() > 0 ? 200 : 204);
        } catch (NoSuchFileException e) {
            return new Pair<>(null, 404);
        } catch (IOException e) {
            return new Pair<>(null, 500);
        }
    }

    public int copyFile(String fromPath, String toPath) {
        try {
            Path sourcePath = Path.of(fromPath);
            Path targetPath = Path.of(toPath);
            Files.copy(sourcePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (NoSuchFileException e) {
            return 404;
        } catch (IOException e) {
            return 500;
        }
        return 204;
    }

    public int deleteFile(String path) {
        try {
            Path filePath = Path.of(path);
            Files.delete(filePath);
        } catch (NoSuchFileException e) {
            return 404;
        } catch (IOException e) {
            return 500;
        }
        return 204;
    }
}
