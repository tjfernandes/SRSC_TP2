package org.example;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.utils.*;

import java.awt.event.*;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class CommandApp {

    public static final String KEYSTORE_TYPE = "JKS";
    public static final String KEYSTORE_PASSWORD = "client_password";
    public static final String KEYSTORE_PATH = "/keystore.jks";
    public static final String TRUSTSTORE_TYPE = "JKS";
    public static final char[] TRUSTSTORE_PASSWORD = "client_truststore_password".toCharArray();
    public static final String TRUSTSTORE_PATH = "/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final String DISPATCHER_HOST = "localhost";
    public static final int DISPATCHER_PORT = 8080;

    private static final String TGS_ID = "access_control";
    private static final String CLIENT_ADDR = "127.0.0.1";
    private static final String SERVICE_ID = "storage";

    private static Map<String, UserInfo> mapUsers;

    private static final long TIMEOUT = 60000;

    private static final Properties properties = new Properties();

    static {
        try (InputStream input = CommandApp.class.getClassLoader()
                .getResourceAsStream("tls-config.properties")) {
            properties.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static final String[] TLS_PROT_ENF = properties.getProperty("TLS-PROT-ENF").split(",");
    public static final String[] CIPHERSUITES = properties.getProperty("CIPHERSUITES").split(",");
    public static final String TLS_AUTH = properties.getProperty("TLS-AUTH");

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
                            lr.getMessage());
                }
            });
            logger.addHandler(handler);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeySpecException {
        // Set the logger level
        logger.setLevel(Level.INFO);

        mapUsers = new HashMap<>();

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
        final AtomicReference<byte[]> payload = new AtomicReference<>();
        final AtomicReference<byte[]> metadata = new AtomicReference<>();
        submitFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Implement file submission logic here
                // This could involve opening a file chooser dialog and processing the selected
                // file
                // For example:
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(null);

                if (result == JFileChooser.APPROVE_OPTION) {
                    // Get the selected file
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        BasicFileAttributes attrs = Files.readAttributes(selectedFile.toPath(),
                                BasicFileAttributes.class);
                        metadata.set(serialize(new FileMetadata(attrs)));
                        payload.set(Files.readAllBytes(selectedFile.toPath()));
                    } catch (IOException ex) {
                        logger.warning("Error reading file: " + ex.getMessage());
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
            final AtomicReference<String> response = new AtomicReference<>();
            if (fullCommand.length > 1) {
                String username = fullCommand[1];

                if (fullCommand[0].equals("login")) {
                    if (fullCommand.length != 3)
                        response.set("Command format should be: login username password");
                    else {
                        try {
                            TimeoutUtils.runWithTimeout(() -> {
                                SecretKey key = performDHKeyExchange(initTLSSocket());
                                mapUsers.putIfAbsent(username, new UserInfo());
                                mapUsers.get(username).setDhKey(key);
                                mapUsers.get(username).setKeyPassword(fullCommand[2]);
                            }, TIMEOUT);
                            TimeoutUtils.runWithTimeout(() -> {
                                try {
                                    processLogin(initTLSSocket(), username, fullCommand[2]);
                                    response.set("User '" + username + "' authenticated with success!");
                                } catch (Exception e1) {
                                    logger.warning("Error processing login: " + e1.getMessage());
                                    response.set(e1.getMessage());
                                }
                            }, TIMEOUT);
                        } catch (TimeoutException ex) {
                            response.set(ex.getMessage());
                        }
                    }
                } else {
                    UserInfo userInfo = mapUsers.get(username);
                    if (userInfo != null) {
                        if (userInfo.getTGT() != null) {
                            SSLSocket socket = initTLSSocket();
                            AtomicReference<CommandReturn> commandReturn = new AtomicReference<>();
                            try {
                                TimeoutUtils.runWithTimeout(() -> {
                                    try {
                                        if (payload.get() == null) {
                                            commandReturn.set(requestCommand(socket, fullCommand, null));
                                            processResponse(fullCommand[0], response, userInfo, commandReturn);
                                        } else {
                                            byte[] encryptedPayload = CryptoStuff.getInstance()
                                                    .encrypt(userInfo.getKeyPassword(), payload.get());
                                            byte[] encryptedMetadata = CryptoStuff.getInstance()
                                                    .encrypt(userInfo.getKeyPassword(), metadata.get());

                                            FilePayload filePayload = new FilePayload(encryptedMetadata,
                                                    encryptedPayload);
                                            commandReturn.set(requestCommand(socket, fullCommand,
                                                    filePayload));

                                            processResponse(fullCommand[0], response, userInfo, commandReturn);
                                        }
                                    } catch (Exception e1) {
                                        logger.warning("Error processing command: " + e1.getMessage());
                                        response.set(e1.getMessage());
                                    }
                                }, TIMEOUT);

                            } catch (TimeoutException ex) {
                                response.set(ex.getMessage());
                            }
                        } else
                            response.set("User '" + fullCommand[1] + "' is not authenticated.\n" +
                                    "Authenticate user with command: login username password");
                    } else
                        response.set("User '" + fullCommand[1] + "' is not authenticated.\n" +
                                "Authenticate user with command: login username password");
                }
            }
            outputText.setText(response + "\n");
            commandTextField.setText("");
        });

        JPanel buttonsPanel = new JPanel(
                new FlowLayout(FlowLayout.CENTER));
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
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            socket = (SSLSocket) sslSocketFactory.createSocket(DISPATCHER_HOST, DISPATCHER_PORT);
            socket.setEnabledProtocols(TLS_PROT_ENF);
            socket.setEnabledCipherSuites(CIPHERSUITES);
            boolean needAuth = TLS_AUTH.equals("MUTUAL");
            // socket.setNeedClientAuth(needAuth);
            socket.setUseClientMode(!needAuth);

            socket.startHandshake();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

    private static void processLogin(SSLSocket socket, String clientId, String password) throws Exception {
        // Handle auth
        logger.severe("Starting authentication");
        sendAuthRequest(socket, clientId);
        mapUsers.get(clientId).setTGT(processAuthResponse(socket, clientId, password));
    }

    private static CommandReturn requestCommand(SSLSocket socket, String[] fullCommand, FilePayload filePayload)
            throws Exception {
        logger.severe("Requesting command: " + fullCommand[0]);
        Authenticator authenticator = null;
        byte[] authenticatorSerialized = null;
        Command command = null;
        String commandString = fullCommand[0];
        String clientId = fullCommand[1];
        switch (fullCommand[0]) {
            case "ls", "mkdir":
                if (fullCommand.length < 2 || fullCommand.length > 4)
                    throw new Exception(
                            "Command format should be: " + fullCommand[0] + " username path");
                if (fullCommand.length == 2) {
                    command = new Command(fullCommand[0], clientId, "/");
                } else {
                    command = new Command(fullCommand[0], clientId, fullCommand[2]);
                }
                break;
            case "put":
                if (fullCommand.length != 3)
                    throw new Exception(
                            "Command format should be: " + fullCommand[0] + "username path/file");
                logger.info("File payload: " + filePayload);
                command = new Command(fullCommand[0], clientId, filePayload, fullCommand[2]);
                break;
            case "get", "rm", "file":
                if (fullCommand.length != 3)
                    throw new Exception(
                            "Command format should be: " + fullCommand[0] + "username path/file");
                command = new Command(fullCommand[0], clientId, fullCommand[2]);
                break;
            case "cp":
                if (fullCommand.length != 4)
                    throw new Exception(
                            "Command format should be: " + fullCommand[0] + "username path1/file1 path2/file2");

                command = new Command(fullCommand[0], clientId, filePayload, fullCommand[2], fullCommand[3]);
                break;
            default:
                throw new Exception("Command '" + fullCommand[0] + "' is invalid");
        }
        // Request SGT from TGS
        authenticator = new Authenticator(clientId, CLIENT_ADDR, command);

        authenticatorSerialized = serialize(authenticator);

        ResponseAuthenticationMessage tgt = mapUsers.get(clientId).getTGT();
        sendTGSRequest(socket, tgt.getEncryptedTGT(),
                CryptoStuff.getInstance()
                        .encrypt(tgt.getGeneratedKey(),
                                authenticatorSerialized),
                command);

        mapUsers.get(clientId).addSGT(commandString,
                processTGSResponse(socket, tgt.getGeneratedKey()));

        SSLSocket serviceSocket = initTLSSocket();
        ResponseTGSMessage sgt = mapUsers.get(clientId).getSGT(commandString);
        logger.info("Sending service request");
        sendServiceRequest(serviceSocket, command, sgt);

        // Communication logic with the server
        logger.info("Waiting for service response");
        ObjectInputStream ois = new ObjectInputStream(serviceSocket.getInputStream());
        Wrapper wrapper = (Wrapper) ois.readObject();

        return processResponse(wrapper, sgt.getSessionKey(), clientId, commandString);
    }

    private static CommandReturn processResponse(Wrapper wrapper, SecretKey sessionKey, String clientId,
            String command) throws Exception {
        logger.info("Processing service response status");
        MessageStatus status = MessageStatus.fromCode(wrapper.getStatus());

        logger.info("Status: " + status);
        switch (status) {
            case OK, OK_NO_CONTENT:
                byte[] encryptedResponse = wrapper.getMessage();
                byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(sessionKey, encryptedResponse);
                return ((ResponseServiceMessage) deserialize(decryptedResponse)).getcommandReturn();

            case BAD_REQUEST:
                throw new Exception("Command '" + command + "' is invalid");
            case UNAUTHORIZED:
                throw new Exception("User '" + clientId + "' is not authenticated");
            case FORBIDDEN:
                throw new Exception("User '" + clientId + "' is not authorized");
            case NOT_FOUND:
                throw new Exception("File not found");
            case INTERNAL_SERVER_ERROR:
                throw new Exception("Internal server error");
            case CONFLICT:
                throw new Exception("File already exists");
            default:
                throw new Exception("Error processing response");
        }
    }

    public static void sendAuthRequest(SSLSocket socket, String clientId) {
        try {
            logger.severe("Sending auth request for client: " + clientId);

            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestAuthenticationMessage requestMessage = new RequestAuthenticationMessage(clientId, CLIENT_ADDR,
                    TGS_ID);

            byte[] encryptedRequestMessge = CryptoStuff.getInstance().encrypt(mapUsers.get(clientId).getDhKey(),
                    serialize(requestMessage));

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 1, encryptedRequestMessge, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void sendTGSRequest(SSLSocket socket, byte[] encryptedTGT, byte[] encryptedAuthenticator,
            Command command) {
        try {
            logger.severe("Sending TGS request command: " + command.getCommand() + " for client: "
                    + command.getUsername() + " to service: " + SERVICE_ID);
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            RequestTGSMessage requestMessage = new RequestTGSMessage(SERVICE_ID, encryptedTGT, encryptedAuthenticator);

            byte[] requestMessageSerialized = serialize(requestMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 3, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendServiceRequest(SSLSocket socket, Command command, ResponseTGSMessage sgt) {
        try {
            logger.severe("Sending Storage request command: " + command.getCommand() + " for client: "
                    + command.getUsername() + " to service: " + SERVICE_ID);
            // Communication logic with the server
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            Authenticator authenticator = new Authenticator(command.getUsername(), CLIENT_ADDR);
            byte[] encryptedAuthenticator = CryptoStuff.getInstance().encrypt(
                    sgt.getSessionKey(),
                    serialize(authenticator));

            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(sgt.getSgt(),
                    encryptedAuthenticator, command);
            byte[] requestMessageSerialized = serialize(requestServiceMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 6, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static ResponseAuthenticationMessage processAuthResponse(SSLSocket socket, String clientId,
            String password) throws Exception {
        logger.severe("Processing auth response for client: " + clientId);
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            Wrapper wrapper = (Wrapper) ois.readObject();
            MessageStatus responseStatus = MessageStatus.fromCode(wrapper.getStatus());
            switch (responseStatus) {
                case OK:
                    byte[] encryptedResponse = wrapper.getMessage();
                    try {
                        SecretKey clientKey = mapUsers.get(clientId).getKeyPassword();
                        byte[] descryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);
                        responseAuthenticationMessage = (ResponseAuthenticationMessage) deserialize(descryptedResponse);
                    } catch (CryptoException e) {
                        throw new Exception("This password is incorrect.");
                    }
                    break;
                case UNAUTHORIZED:
                    throw new Exception("Wrong username or password.");
                default:
                    throw new Exception("Unexpected response status: " + responseStatus);
            }
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return responseAuthenticationMessage;
    }

    public static ResponseTGSMessage processTGSResponse(SSLSocket socket, SecretKey key) throws Exception {
        logger.severe("Processing TGS response");
        ResponseTGSMessage responseTGSMessage = null;

        // Communication logic with the server
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(socket.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }

        logger.info("Waiting for TGS response");
        Wrapper wrapper = null;
        try {
            wrapper = (Wrapper) ois.readObject();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (wrapper.getStatus() == MessageStatus.FORBIDDEN.getCode()) {
            throw new Exception("User is trying to use ../ on a absolute path");
        } else if (wrapper.getStatus() == MessageStatus.UNAUTHORIZED.getCode()) {
            throw new Exception("User does not have permission to do that operation");
        }
        logger.info("Attempting to decrypt TGS response");
        // int responseStatus = wrapper.getStatus();
        byte[] encryptedResponse = wrapper.getMessage();
        byte[] decryptedResponse = null;
        try {
            decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        logger.info("Attempting to deserialize TGS response");
        try {
            responseTGSMessage = (ResponseTGSMessage) deserialize(decryptedResponse);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        logger.info("Finished processing TGS response");

        return responseTGSMessage;
    }

    public static ResponseServiceMessage processServiceResponse(SSLSocket socket,
            ResponseTGSMessage responseTGSMessage) {
        logger.severe("Processing Storage response");
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

    private static void processResponse(String command, AtomicReference<String> response, UserInfo userInfo,
            AtomicReference<CommandReturn> commandReturn) {
        if (commandReturn.get().getPayload() != null) {
            byte[] payloadReceived = commandReturn.get().getPayload();
            if (payloadReceived.length > 0) {
                switch (command) {
                    case "ls":
                        response.set(new String(payloadReceived));
                        break;
                    case "mkdir":
                        response.set("Folder created successfully.");
                        break;
                    case "put":
                        response.set("File uploaded successfully.");
                        break;
                    case "get":
                        response.set(getProcess(payloadReceived,
                                userInfo.getKeyPassword()));
                        break;
                    case "rm":
                        response.set("File removed successfully.");
                        break;
                    case "cp":
                        response.set("File copied successfully.");
                        break;
                    case "file":
                        try {
                            byte[] decryptedPayload = CryptoStuff.getInstance().decrypt(userInfo.getKeyPassword(),
                                    payloadReceived);

                            ByteArrayInputStream bis = new ByteArrayInputStream(decryptedPayload);
                            ObjectInput in = new ObjectInputStream(bis);
                            FileMetadata fileMetadata = (FileMetadata) in.readObject();
                            response.set(fileMetadata.toString());

                        } catch (InvalidAlgorithmParameterException e) {
                            e.printStackTrace();
                        } catch (CryptoException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (ClassNotFoundException e) {
                            e.printStackTrace();
                        }
                        break;
                    default:
                        response.set("Command not recognized.");
                        break;
                }
            } else {
                response.set("There is no content to be displayed.");
            }
        } else {
            response.set("");
        }
    }

    private static String getProcess(byte[] payloadReceived, SecretKey key) {
        String userHome = System.getProperty("user.home");
        String downloadsDir;
        String fileName = UUID.randomUUID().toString();

        // Determine the default downloads directory based on the operating system
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            downloadsDir = userHome + "\\Downloads\\"; // For Windows
        } else if (os.contains("mac")) {
            downloadsDir = userHome + "/Downloads/"; // For Mac
        } else if (os.contains("nux") || os.contains("nix")) {
            downloadsDir = userHome + "/Downloads/"; // For Linux/Unix
        } else {
            downloadsDir = userHome + "/"; // For other systems
        }

        // Create the directory if it doesn't exist
        File directory = new File(downloadsDir);
        if (!directory.exists()) {
            directory.mkdir();
        }

        // Append the filename to the directory
        String filePath = downloadsDir + fileName;
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            byte[] decryptedData = CryptoStuff.getInstance().decrypt(key, payloadReceived);
            fos.write(decryptedData);
            return "File downloaded successfully to: " + filePath;
        } catch (Exception ex) {
            ex.printStackTrace();
            return "File wasn't successfully downloaded in dir: " + filePath;
        }
    }

    private static SecretKey performDHKeyExchange(SSLSocket socket) {

        logger.severe("Performing DH key exchange");
        // Generate DH parameters
        try {
            logger.info("Generating DH parameters");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048); // Adjust the key size as needed
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Generate public key and send it to the other endpoint
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            logger.info("Trying to start outstream");
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            logger.info("Sending public key to server");
            Wrapper request = new Wrapper((byte) 0, publicKeyBytes, UUID.randomUUID());
            logger.info("Request: " + request);
            oos.writeObject(request);
            oos.flush();

            logger.info("Waiting for public key from server");
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            Wrapper response = (Wrapper) ois.readObject();

            // Generate public key from received bytes
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(response.getMessage());
            PublicKey receivedPublicKey = keyFactory.generatePublic(publicKeySpec);

            // Perform the DH key agreement
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(receivedPublicKey, true);

            // Generate the shared secret
            byte[] sharedSecret = keyAgreement.generateSecret();

            // Derive a symmetric key from the shared secret
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] derivedKey = messageDigest.digest(sharedSecret);
            SecretKey secretKey = new SecretKeySpec(derivedKey, "AES");

            return secretKey;

        } catch (Exception e) {
            logger.warning("Error performing DH key exchange: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
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
}