package org.example;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.exceptions.IncorrectPasswordException;
import org.example.exceptions.InvalidCommandException;
import org.example.exceptions.UserNotFoundException;
import org.example.utils.*;

import java.awt.event.*;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class CommandApp {

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



    private static final String HASHING_ALGORITHMS = "PBKDF2WithHmacSHA256";

    private static final String TGS_ID = "access_control";
    private static final String CLIENT_ADDR = "127.0.0.1";
    private static final String SERVICE_ID = "storage";
    private static final byte[] salt = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,0x0f, 0x0d, 0x0e, 0x0c, 0x07, 0x06, 0x05, 0x04};
    private static ResponseAuthenticationMessage responseAuthenticationMessage = null;
    private static ResponseTGSMessage responseTGSMessage = null;

    // Custom logger to print the timestamp in milliseconds
    private static final Logger logger = Logger.getLogger(CommandApp.class.getName());
    static {
        try {
            Logger rootLogger = Logger.getLogger("");
            Handler[] handlers = rootLogger.getHandlers();
            if (handlers[0] instanceof ConsoleHandler) {
                rootLogger.removeHandler(handlers[0]);
            }
    
            ConsoleHandler handler = new ConsoleHandler();
            handler.setFormatter(new SimpleFormatter() {
                private static final String format = "[%1$tT,%1$tL] [%2$-7s] [%3$s]: %4$s %n";
    
                @Override
                public synchronized String format(LogRecord lr) {
                    return String.format(format,
                            new Date(lr.getMillis()),
                            lr.getLevel().getLocalizedName(),
                            lr.getLoggerName(),
                            lr.getMessage()
                    );
                }
            });
            logger.addHandler(handler);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        // Set the logger level
        logger.setLevel(Level.SEVERE);


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
            String response = null;
            if (fullCommand[0].equals("login")) {
                if (fullCommand.length != 3)
                    throw new InvalidCommandException("Command format should be: login username password");
                SSLSocket socket = initTLSSocket();
                try {
                    processLogin(socket, fullCommand[1], fullCommand[2]);
                    response = "User '" + fullCommand[1] + "' authenticated with success!";
                } catch (UserNotFoundException | IncorrectPasswordException ex) {
                    response = ex.getMessage();
                }
            } else {
                if (responseAuthenticationMessage != null) {
                    response = "Command: " + command;
                    SSLSocket socket = initTLSSocket();
                    CommandReturn commandReturn = requestCommand(socket, fullCommand, payload[0]);

                    byte[] payloadReceived = commandReturn.getPayload();
                    if (payloadReceived.length > 0) {
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
            trustStore.load(CommandApp.class.getResourceAsStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

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

    private static void processLogin(SSLSocket socket, String clientId, String password) throws UserNotFoundException, IncorrectPasswordException {
        // Handle auth
        sendAuthRequest(socket, clientId);
        responseAuthenticationMessage = processAuthResponse(socket, clientId, password);
    }

    private static CommandReturn requestCommand(SSLSocket socket,  String[] fullCommand, byte[] payload) {
        CommandReturn commandReturn = null;
        Authenticator authenticator = null;
        byte[] authenticatorSerialized = null;
        Command command;
        ResponseServiceMessage responseServiceMessage;
        try {
            switch (fullCommand[0]) {
                case "ls", "mkdir":
                    if (fullCommand.length < 2 || fullCommand.length > 3)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + " username path");
                    if (fullCommand.length == 2){
                        command = new Command(fullCommand[0], fullCommand[1], null);
                    } else {
                        command = new Command(fullCommand[0], fullCommand[1], fullCommand[2]);
                    }
                    // Request SGT from TGS
                    authenticator = new Authenticator(fullCommand[1], CLIENT_ADDR, command);
                    
                    authenticatorSerialized = serialize(authenticator);
                    sendTGSRequest(socket, responseAuthenticationMessage.getEncryptedTGT(), CryptoStuff.getInstance().encrypt(responseAuthenticationMessage.getGeneratedKey(), authenticatorSerialized), command);

                    responseTGSMessage = processTGSResponse(socket, responseAuthenticationMessage.getGeneratedKey());


                    SSLSocket serviceSocket = initTLSSocket();
                    sendServiceRequest(serviceSocket, command);
                    responseServiceMessage = processServiceResponse(socket);

                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "put":
                    if (fullCommand.length != 3)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + "username path/file");

                    command = new Command(fullCommand[0], fullCommand[1], payload, fullCommand[2]);

                    // Request SGT from TGS
                    authenticator = new Authenticator(fullCommand[1], CLIENT_ADDR, command);
                    authenticatorSerialized = serialize(authenticator);
                    sendTGSRequest(socket, responseAuthenticationMessage.getEncryptedTGT(),
                            CryptoStuff.getInstance().encrypt(responseAuthenticationMessage.getGeneratedKey(), authenticatorSerialized), command);

                    responseTGSMessage = processTGSResponse(socket, responseAuthenticationMessage.getGeneratedKey());

                    sendServiceRequest(socket, command);
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "get, rm":
                    if (fullCommand.length != 2)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + "username path/file");

                    command = new Command(fullCommand[0], fullCommand[1], fullCommand[1]);

                    // Request SGT from TGS
                    authenticator = new Authenticator(fullCommand[1], CLIENT_ADDR, command);
                    authenticatorSerialized = serialize(authenticator);
                    sendTGSRequest(socket, responseAuthenticationMessage.getEncryptedTGT(),
                            CryptoStuff.getInstance().encrypt(responseAuthenticationMessage.getGeneratedKey(), authenticatorSerialized), command);

                    responseTGSMessage = processTGSResponse(socket, responseAuthenticationMessage.getGeneratedKey());

                    sendServiceRequest(socket, command);
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "cp":
                    if (fullCommand.length != 4)
                        throw new InvalidCommandException("Command format should be: " + fullCommand[0] + "username path1/file1 path2/file2");

                    command = new Command(fullCommand[0], fullCommand[1], payload, fullCommand[2], fullCommand[3]);

                    // Request SGT from TGS
                    authenticator = new Authenticator(fullCommand[1], CLIENT_ADDR, command);
                    authenticatorSerialized = serialize(authenticator);
                    sendTGSRequest(socket, responseAuthenticationMessage.getEncryptedTGT(),
                            CryptoStuff.getInstance().encrypt(responseAuthenticationMessage.getGeneratedKey(), authenticatorSerialized), command);

                    responseTGSMessage = processTGSResponse(socket, responseAuthenticationMessage.getGeneratedKey());

                    System.out.println("Sending service request");
                    sendServiceRequest(socket, command);
                    System.out.println("Processing service response");
                    responseServiceMessage = processServiceResponse(socket);
                    commandReturn = responseServiceMessage.getcommandReturn();

                    break;
                case "file":
                    // TODO - construtores do CommandApp não consistentes com o enunciado? ou tripei?
                    break;
                default:
                    throw new InvalidCommandException("Command '" + fullCommand[0] + "' is invalid");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return commandReturn;
    }

    public static void sendAuthRequest(SSLSocket socket, String clientId) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestAuthenticationMessage requestMessage = new RequestAuthenticationMessage(clientId, CLIENT_ADDR, TGS_ID);

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

    public static void sendTGSRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator, Command command) {
        try {
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestTGSMessage requestMessage = new RequestTGSMessage(SERVICE_ID, encryptedTGT, encryptedAuthenticator);

            byte[] requestMessageSerialized = serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 3, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            System.out.println("Sending TGS request: " + wrapper);
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendServiceRequest(SSLSocket socket, Command command) {
        try {
            System.out.println("Sending service request");
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            Authenticator authenticator = new Authenticator(command.getUsername(), CLIENT_ADDR, command);
            byte[] encryptedAuthenticator = CryptoStuff.getInstance().encrypt(responseTGSMessage.getSessionKey(), serialize(authenticator));

            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(responseTGSMessage.getSgt(), encryptedAuthenticator);
            byte[] requestMessageSerialized = serialize(requestServiceMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 6, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            System.out.println("Sending service request: " + wrapper);
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static ResponseAuthenticationMessage processAuthResponse(SSLSocket socket, String clientId, String password) throws IncorrectPasswordException, UserNotFoundException {
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            int responseStatus = wrapper.getStatus();
            switch (responseStatus) {
                case 200:
                    byte[] encryptedResponse = wrapper.getMessage();
                    try {
                        SecretKey clientKey = CryptoStuff.getInstance().convertByteArrayToSecretKey(hashPassword(password));
                        byte[] descryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);
                        responseAuthenticationMessage = (ResponseAuthenticationMessage) deserialize(descryptedResponse);
                    } catch (CryptoException e) {
                        throw new IncorrectPasswordException("This password is incorrect.");
                    }
                    break;
                case 401:
                    throw new UserNotFoundException("User '" + clientId + "' does not exist");
                default:
                    break;
            }
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return responseAuthenticationMessage;
    }

    public static ResponseTGSMessage processTGSResponse(SSLSocket socket, SecretKey key) {
        ResponseTGSMessage responseTGSMessage = null;
        try {
            System.out.println("Process TGS response");
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();

            int responseStatus = wrapper.getStatus();

            byte[] encryptedResponse = wrapper.getMessage();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);

            responseTGSMessage = (ResponseTGSMessage) deserialize(decryptedResponse);
            System.out.println("Response TGS message: " + responseTGSMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseTGSMessage;
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

    private static byte[] hashPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        int keyLength = 256;

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASHING_ALGORITHMS);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        System.out.println("Hashed password: " + Base64.getEncoder().encodeToString(hash));
        return hash;
    }

//    private static String bytesToHex(byte[] bytes) {
//        StringBuilder sb = new StringBuilder();
//        for (byte b : bytes) {
//            sb.append(String.format("%02x", b));
//        }
//        return sb.toString();
//    }


}