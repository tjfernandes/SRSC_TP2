package org.example;


import org.example.crypto.CryptoStuff;
import org.example.utils.*;

import java.awt.event.*;
import javax.crypto.SecretKey;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

public class RemoteFileSystemApp {

    public static final String[] CONFPROTOCOLS     = {"TLSv1.2"};
    public static final String[] CONFCIPHERSUITES  = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_TYPE       = "JKS";
    public static final String KEYSTORE_PASSWORD   = "client_password";
    public static final String KEYSTORE_PATH       = "/keystore.jks";
    public static final String TRUSTSTORE_TYPE     = "JKS";
    public static final char[] TRUSTSTORE_PASSWORD = "client_truststore_password".toCharArray();
    public static final String TRUSTSTORE_PATH     = "/truststore.jks";
    public static final String TLS_VERSION         = "TLSv1.2";
    public static final String DISPATCHER_HOST     = "localhost";
    public static final int DISPATCHER_PORT        = 8080;



    private static final String HASHING_ALGORITHMS = "SHA-256";
    private static final String CLIENT_PASS = "12345";

    private static final String TGS_ID = "access_control";
    private static final String CLIENT_ID = "client";
    private static final String CLIENT_ADDR = "127.0.0.1";
    private static final String SERVICE_ID = "storage";
    private static final byte[] salt = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,0x0f, 0x0d, 0x0e, 0x0c, 0x07, 0x06, 0x05, 0x04};;

    public static void main(String[] args) {
        JFrame frame = new JFrame("Remote FS");
        frame.setSize(800, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(35, 35, 35, 35));

        JLabel inputInstruction = new JLabel("Enter your command");
        JTextField commandTextField = new JTextField();
        JTextArea outputText = new JTextArea();
        outputText.setLineWrap(true);
        outputText.setWrapStyleWord(true);
        outputText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputText);
        scrollPane.setPreferredSize(new Dimension(750, 300));

        JButton requestButton = getjButton(commandTextField, outputText);

        panel.add(inputInstruction);
        panel.add(commandTextField);
        panel.add(requestButton);
        panel.add(scrollPane);

        frame.add(panel);
        frame.setVisible(true);
    }

    private static JButton getjButton(JTextField commandTextField, JTextArea outputText) {
        JButton requestButton = new JButton("Request");
        requestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String command = commandTextField.getText();
                String response = "";
                try {
                    response = requestCommand(command);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                outputText.append(response + "\n");
                commandTextField.setText("");
            }
        });
        return requestButton;
    }

    private static String requestCommand(String command) throws IOException {

        try {
            SSLSocket socket = initTLSSocket();

            String[] fullCommand = command.split("\\s+");

            byte messageType;
            if (fullCommand[0].equals("login")) {
                processLogin(socket);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "response";
    }

    private static SSLSocket initTLSSocket() {
        SSLSocket socket = null;
        try {

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(RemoteFileSystemApp.class.getResourceAsStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            System.out.println("HOST: " + DISPATCHER_HOST);
            System.out.println("PORT: " + DISPATCHER_PORT);

            socket = (SSLSocket) sslSocketFactory.createSocket(DISPATCHER_HOST, DISPATCHER_PORT);
            socket.setUseClientMode(true);
            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            socket.startHandshake();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

    private static void processLogin(SSLSocket socket) {
        try {

            // Handle auth
            Login.sendAuthRequest(socket);
            ResponseAuthenticationMessage responseAuthenticationMessage = Login.processAuthResponse(socket);
            byte[] encryptedTGT = responseAuthenticationMessage.getEncryptedTGT();
            SecretKey clientTGSKey = responseAuthenticationMessage.getGeneratedKey();

            // Handle TGS
            Authenticator authenticator = new Authenticator(CLIENT_ID, CLIENT_ADDR);
            byte[] authenticatorSerialized = serialize(authenticator);
            Login.sendTGSRequest(socket, encryptedTGT, CryptoStuff.getInstance().encrypt(clientTGSKey, authenticatorSerialized));

            ResponseTGTMessage responseTGTMessage = Login.processTGSResponse(socket, encryptedTGT, clientTGSKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendAuthRequest(SSLSocket socket) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestAuthenticationMessage requestMessage = new RequestAuthenticationMessage(CLIENT_ID, CLIENT_ADDR, TGS_ID);

            byte[] requestMessageSerialized = serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendTGSRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestTGSMessage requestMessage = new RequestTGSMessage(SERVICE_ID, encryptedTGT, encryptedAuthenticator);

            byte[] requestMessageSerialized = serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendServiceRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator) {
//        Req requestServiceMessage = null;
//        try {
//            // Communication logic with the server
//            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
//
//
//
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }

    private static ResponseAuthenticationMessage processAuthResponse(SSLSocket socket) {
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            byte[] encryptedResponse = wrapper.getMessage();

            SecretKey clientKey = CryptoStuff.getInstance().convertStringToSecretKeyto(hashPassword(CLIENT_PASS));
            byte[] descryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);

            responseAuthenticationMessage = (ResponseAuthenticationMessage) deserialize(descryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseAuthenticationMessage;
    }

    private static ResponseTGTMessage processTGSResponse(SSLSocket socket, byte[] encryptedTGT, SecretKey key) {
        ResponseTGTMessage responseTGTMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();

            byte[] encryptedResponse = wrapper.getMessage();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);

            responseTGTMessage = (ResponseTGTMessage) deserialize(decryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseTGTMessage;
    }

    private static byte[] serialize(Object object) throws IOException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(object);
            objectOutputStream.flush();
            return byteArrayOutputStream.toByteArray();
        }
    }

    private static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
             ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {
            return objectInputStream.readObject();
        }
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHMS);
        md.update(salt);
        byte[] bytes = md.digest(password.getBytes());
        return bytesToHex(bytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


}