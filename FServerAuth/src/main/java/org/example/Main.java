package org.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Main {
    public static void main(String[] args) {
        try {
            // Load your keystore and truststore here
            System.setProperty("javax.net.ssl.keyStore", "src/main/java/server-keystore.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "your_keystore_password");
            System.setProperty("javax.net.ssl.trustStore", "src/main/java/server.crt");
            System.setProperty("javax.net.ssl.trustStorePassword", "your_truststore_password");

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket("localhost", 8080);

            // Communication logic with the server
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

            // Example message to send
            String message = "Hello, Server!";
            writer.write(message);
            writer.newLine();
            writer.flush();

            // Read the server's response
            String response = reader.readLine();
            System.out.println("Server response: " + response);

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}