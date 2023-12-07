package org.example.utils;

import java.io.Serial;
import java.io.Serializable;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;

public class FileMetaData implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final long size;
    private final FileTime creationTime;
    private final FileTime lastAccessTime;
    private final FileTime lastModifiedTime;
    private final boolean isDirectory;
    private final boolean isRegularFile;
    private final boolean isSymbolicLink;
    private final boolean isOther;

    public FileMetaData(BasicFileAttributes attrs) {
        this.size = attrs.size();
        this.creationTime = attrs.creationTime();
        this.lastAccessTime = attrs.lastAccessTime();
        this.lastModifiedTime = attrs.lastModifiedTime();
        this.isDirectory = attrs.isDirectory();
        this.isRegularFile = attrs.isRegularFile();
        this.isSymbolicLink = attrs.isSymbolicLink();
        this.isOther = attrs.isOther();
    }

    public long getSize() {
        return size;
    }

    public FileTime getCreationTime() {
        return creationTime;
    }

    public FileTime getLastAccessTime() {
        return lastAccessTime;
    }

    public FileTime getLastModifiedTime() {
        return lastModifiedTime;
    }

    public boolean isDirectory() {
        return isDirectory;
    }

    public boolean isRegularFile() {
        return isRegularFile;
    }

    public boolean isSymbolicLink() {
        return isSymbolicLink;
    }

    public boolean isOther() {
        return isOther;
    }

    @Override
    public String toString() {
        return "FileMetaData{" +
                "size=" + size +
                ", creationTime=" + creationTime +
                ", lastAccessTime=" + lastAccessTime +
                ", lastModifiedTime=" + lastModifiedTime +
                ", isDirectory=" + isDirectory +
                ", isRegularFile=" + isRegularFile +
                ", isSymbolicLink=" + isSymbolicLink +
                ", isOther=" + isOther +
                '}';
    }

}