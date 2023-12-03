package org.example;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class Authentication {
    private static final String FILE_PATH = "./users.txt";
    private Map<String, User> users;

    public Authentication() {
        File file = new File(FILE_PATH);
        if (file.exists()) {
            users = readUsers();
        } else {
            users = new HashMap<>();
            try {
                file.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    public boolean register(String username, String password) {
        try {
            User user = new User(username, password);
            users.put(username, user);
            writeUsers();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean login(String username, String password) {
        try {
            User user = users.get(username);
            if (user == null) {
                return false;
            }
            String hashedPassword = user.hashPassword(password, user.getSalt());
            return hashedPassword.equals(user.getHashedPassword());
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private void writeUsers() {
        try {
            File file = new File(FILE_PATH);
            if (!file.exists()) {
                file.createNewFile();
            }
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                oos.writeObject(users);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, User> readUsers() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(FILE_PATH))) {
            Object obj = ois.readObject();
            if (obj instanceof Map) {
                return (Map<String, User>) obj;
            } else {
                throw new IOException("Invalid data type in file");
            }
        } catch (EOFException e) {
            return new HashMap<>();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return new HashMap<>();
        }
    }
}