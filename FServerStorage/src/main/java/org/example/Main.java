package org.example;

import com.dropbox.core.DbxException;
public class Main {

    public void lsCommand(){

    }

    public void putCommand(){

    }

    public void getCommand(){

    }

    public void mkdirCommand(){

    }

    public void rmCommand(){

    }

    public void cpCommand(){

    }

    public static void main(String[] args) throws DbxException {
        DropboxDriver dp = new DropboxDriver("src/main/java/dropbox-config.properties");
        LocalFileSystemDriver fs = new LocalFileSystemDriver("src/main/java/filesystem-config.properties");
        fs.uploadFile("src/main/java/ola.txt","ola.txt");
        dp.uploadFile("src/main/java/ola.txt","ola.txt");
    }
}