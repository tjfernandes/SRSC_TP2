package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");



        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream("config.properties")) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String algorithm = props.getProperty("algorithm");
        String mode = props.getProperty("mode");
        String padding = props.getProperty("padding");
        String iv = props.getProperty("iv");
    }
}   