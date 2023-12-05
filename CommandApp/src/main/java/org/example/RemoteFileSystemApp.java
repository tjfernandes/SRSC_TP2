package org.example;


import org.example.crypto.CryptoStuff;
import org.example.utils.*;

import java.awt.event.*;
import javax.crypto.SecretKey;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
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
    private static ResponseTGSMessage responseTGSMessage;


    public static void main(String[] args) {
        JFrame frame = new JFrame("Remote FS");
        frame.setSize(800, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        JLabel inputInstruction = new JLabel("Enter your command");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(inputInstruction, gbc);

        JTextField commandTextField = new JTextField(50);
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(commandTextField, gbc);

        JTextArea outputText = new JTextArea();
        outputText.setLineWrap(true);
        outputText.setWrapStyleWord(true);
        outputText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputText);
        scrollPane.setPreferredSize(new Dimension(750, 200));

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(scrollPane, gbc);

        JLabel fileNameLabel = new JLabel();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(fileNameLabel, gbc);

        JButton submitFileButton = new JButton("Submit File");
        final byte[][] payload = new byte[1][1];
        submitFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Implement file submission logic here
                // This could involve opening a file chooser dialog and processing the selected file
                // For example:
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(null);

                if (result == JFileChooser.APPROVE_OPTION) {
                    // Get the selected file
                    File selectedFile = fileChooser.getSelectedFile();

                    try {
                        payload[0] = Files.readAllBytes(selectedFile.toPath());
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }

                    // Process the selected file (you can define your logic here)
                    // For now, let's print the file name
                    fileNameLabel.setText("Selected file: " + selectedFile.getName());
                }
            }
        });

        JButton requestButton = new JButton("Request");
        requestButton.addActionListener(e -> {
            String command = commandTextField.getText();
            String[] fullCommand = command.split(" ");
            String response = "";
            try {
                SSLSocket socket = initTLSSocket();
                if (fullCommand[0].equals("login")) {
                    processLogin(socket);
                    response = "User '" + fullCommand[1] + "' authenticated with success!";
                } else {
                    if (responseTGSMessage == null) {
                        CommandReturn commandReturn = requestCommand(socket, fullCommand, payload[0]);
                        byte[] payloadReceived = payload[0];
                        if (!Arrays.equals(payloadReceived, new byte[0])) {
                            String userHome = System.getProperty("user.home");
                            String downloadsDir;

                            String fileName = UUID.randomUUID().toString();

                            // Determine the default downloads directory based on the operating system
                            String os = System.getProperty("os.name").toLowerCase();
                            if (os.contains("win")) {
                                downloadsDir = userHome + "\\Downloads\\" + fileName; // For Windows
                            } else if (os.contains("mac")) {
                                downloadsDir = userHome + "/Downloads/" + fileName; // For Mac
                            } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
                                downloadsDir = userHome + "/Downloads/" + fileName; // For Linux/Unix
                            } else {
                                downloadsDir = userHome + "/" + fileName; // For other systems
                            }

                            try(FileOutputStream fos = new FileOutputStream(downloadsDir)) {
                                fos.write(payloadReceived);
                                response = "File downloaded successfully to: " + downloadsDir;
                            } catch (Exception ex) {
                                response = "File wasn't successfully downloaded in dir: " + downloadsDir;
                            }

                        }
                    } else {
                        response = "User '" + fullCommand[1] + "' is not authenticated.\n" +
                                   "Authenticate user with command: login username password";
                    }
                }

            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
            outputText.setText(response + "\n");
            commandTextField.setText("");
        });

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonsPanel.add(submitFileButton);
        buttonsPanel.add(requestButton);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        panel.add(buttonsPanel, gbc);

        frame.add(panel);
        frame.setVisible(true);
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

            responseTGSMessage = Login.processTGSResponse(socket, encryptedTGT, clientTGSKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static CommandReturn requestCommand(SSLSocket socket,  String[] fullCommand, byte[] payload) {
        CommandReturn commandReturn = null;
        try {
            Command command;
            ResponseServiceMessage responseServiceMessage;
            switch (fullCommand[0]) {
                case "ls", "mkdir":
                    if (fullCommand.length != 3)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + " path");

                    command = new Command(fullCommand[0], fullCommand[2]);
                    sendServiceRequest(socket, command);
                    Thread.sleep(5000);
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "put":
                    if (fullCommand.length != 3)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + "username path/file");

                    command = new Command(fullCommand[0], payload, fullCommand[2]);
                    sendServiceRequest(socket, command);
                    Thread.sleep(5000);
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "get, rm":
                    if (fullCommand.length != 2)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + "username path/file");

                    command = new Command(fullCommand[0], fullCommand[1]);
                    sendServiceRequest(socket, command);
                    Thread.sleep(5000);
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "cp":
                    if (fullCommand.length != 4)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + "username path1/file1 path2/file2");

                    command = new Command(fullCommand[0], payload, fullCommand[2], fullCommand[3]);
                    sendServiceRequest(socket, command);
                    Thread.sleep(5000);
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "file":
                    // TODO - construtores do CommandApp não consistentes com o enunciado?
                    break;
                default:
                    throw new InvalidCommandException("Command '" + fullCommand[0] + "' is invalid");
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return commandReturn;
    }

    private static void sendServiceRequest(SSLSocket socket, Command command) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            Authenticator authenticator = new Authenticator(CLIENT_ID, CLIENT_ADDR);
            byte[] encryptedAuthenticator = CryptoStuff.getInstance().encrypt(responseTGSMessage.getSessionKey(), serialize(authenticator));

            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(responseTGSMessage.getSgt(), encryptedAuthenticator, command);
            byte[] requestMessageSerialized = serialize(requestServiceMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static ResponseServiceMessage processServiceResponse(SSLSocket socket) {
        ResponseServiceMessage responseServiceMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            byte[] encryptedResponse = wrapper.getMessage();

            SecretKey clientServiceKey = responseTGSMessage.getSessionKey();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(clientServiceKey, encryptedResponse);

            responseServiceMessage = (ResponseServiceMessage) deserialize(decryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseServiceMessage;
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