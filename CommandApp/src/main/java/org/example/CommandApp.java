package org.example;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.exceptions.IncorrectPasswordException;
import org.example.exceptions.InvalidCommandException;
import org.example.exceptions.UserNotFoundException;
import org.example.messages.RequestAuthenticationMessage;
import org.example.messages.RequestServiceMessage;
import org.example.messages.RequestTGSMessage;
import org.example.messages.ResponseAuthenticationMessage;
import org.example.messages.ResponseServiceMessage;
import org.example.messages.ResponseTGSMessage;
import org.example.utils.*;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
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

    public static final String[] CONFPROTOCOLS = { "TLSv1.2" };
    public static final String[] CONFCIPHERSUITES = { "TLS_RSA_WITH_AES_256_CBC_SHA256" };
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

    private static final long TIMEOUT = 10000;

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

        // Create the GUI
        GUI gui = new GUI();

        gui.setRequestButtonListener(e -> {
            String command = gui.getCommand();
            String[] fullCommand = command.split(" ");
            final AtomicReference<String> response = new AtomicReference<>();
            if (fullCommand.length > 1) {
                String username = fullCommand[1];

                if (fullCommand[0].equals("login")) {
                    if (fullCommand.length != 3)
                        throw new InvalidCommandException("Command format should be: login username password");
                    try {
                        TimeoutUtils.runWithTimeout(() -> {
                            SecretKey key = performDHKeyExchange(initTLSSocket());
                            mapUsers.putIfAbsent(username, new UserInfo());
                            logger.info("Setting key: " + key);
                            mapUsers.get(username).setDhKey(key);
                            mapUsers.get(username).setKeyPassword(fullCommand[2]);
                        }, TIMEOUT);
                        TimeoutUtils.runWithTimeout(() -> {
                            try {
                                processLogin(initTLSSocket(), username, fullCommand[2]);
                            } catch (UserNotFoundException | IncorrectPasswordException ex) {
                                response.set(ex.getMessage());
                            }
                        }, TIMEOUT);
                        response.set("User '" + username + "' authenticated with success!");
                    } catch (TimeoutException ex) {
                        response.set(ex.getMessage());
                    }
                } else {
                    UserInfo userInfo = mapUsers.get(username);
                    if (userInfo != null) {
                        if (userInfo.getTGT() != null) {
                            SSLSocket socket = initTLSSocket();
                            AtomicReference<CommandReturn> commandReturn = new AtomicReference<>();
                            try {
                                TimeoutUtils.runWithTimeout(() -> {
                                    if (gui.getPayload().get() == null)
                                        try {
                                            commandReturn.set(requestCommand(socket, fullCommand, null));
                                        } catch (InvalidKeyException | ClassNotFoundException
                                                | InvalidAlgorithmParameterException | CryptoException e1) {
                                            logger.warning(e1.getMessage());
                                        } catch (RuntimeException e1) {
                                            response.set(e1.getMessage());
                                        }
                                    else {
                                        byte[] encryptedPayload;
                                        try {
                                            encryptedPayload = CryptoStuff.getInstance()
                                                    .encrypt(userInfo.getKeyPassword(), gui.getPayload().get());
                                            commandReturn.set(requestCommand(socket, fullCommand,
                                                    new FilePayload(gui.getMetadata().get(), encryptedPayload)));
                                        } catch (InvalidKeyException | ClassNotFoundException
                                                | InvalidAlgorithmParameterException | CryptoException e1) {
                                            logger.warning(e1.getMessage());
                                        } catch (RuntimeException e1) {
                                            response.set(e1.getMessage());
                                        }
                                    }
                                }, TIMEOUT);

                                if (commandReturn.get() != null) {
                                    byte[] payloadReceived = commandReturn.get().getPayload();
                                    if (payloadReceived.length > 0) {
                                        switch (fullCommand[0]) {
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
                                                response.set(getProcess(payloadReceived, userInfo.getKeyPassword()));
                                                break;
                                            case "rm":
                                                response.set("File removed successfully.");
                                                break;
                                            case "cp":
                                                response.set("File copied successfully.");
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
            gui.setOutputText(response + "\n");
            gui.setCommand("");
        });
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
            socket.setUseClientMode(true);
            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            socket.startHandshake();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

    private static void processLogin(SSLSocket socket, String clientId, String password)
            throws UserNotFoundException, IncorrectPasswordException {
        // Handle auth
        logger.severe("Starting authentication");
        sendAuthRequest(socket, clientId);
        mapUsers.get(clientId).setTGT(processAuthResponse(socket, clientId, password));
    }

    private static CommandReturn requestCommand(SSLSocket socket, String[] fullCommand, FilePayload filePayload)
            throws InvalidKeyException, ClassNotFoundException, InvalidAlgorithmParameterException, RuntimeException,
            CryptoException {
        logger.severe("Requesting command: " + fullCommand[0]);
        Authenticator authenticator = null;
        byte[] authenticatorSerialized = null;
        Command command = null;
        String commandString = fullCommand[0];
        String clientId = fullCommand[1];
        switch (fullCommand[0]) {
            case "ls", "mkdir":
                if (fullCommand.length < 2 || fullCommand.length > 4)
                    throw new RuntimeException(
                            "Command format should be: " + fullCommand[0] + " username path");
                if (fullCommand.length == 2) {
                    command = new Command(fullCommand[0], clientId, "/");
                } else {
                    command = new Command(fullCommand[0], clientId, fullCommand[2]);
                }
                break;
            case "put":
                if (fullCommand.length != 3)
                    throw new RuntimeException(
                            "Command format should be: " + clientId + "username path/file");
                logger.info("File payload: " + filePayload);
                command = new Command(fullCommand[0], clientId, filePayload, fullCommand[2]);
                break;
            case "get", "rm":
                if (fullCommand.length != 3)
                    throw new RuntimeException(
                            "Command format should be: " + fullCommand[0] + "username path/file");
                command = new Command(fullCommand[0], clientId, fullCommand[2]);
                break;
            case "cp":
                if (fullCommand.length != 4)
                    throw new RuntimeException(
                            "Command format should be: " + fullCommand[0] + "username path1/file1 path2/file2");

                command = new Command(fullCommand[0], clientId, filePayload, fullCommand[2], fullCommand[3]);
                break;
            case "file":
                // TODO - construtores do CommandApp não consistentes com o enunciado? ou
                // tripei? o stor é que tripo assinado:rosa
                break;
            default:
                throw new RuntimeException("Command '" + fullCommand[0] + "' is invalid");
        }
        // Request SGT from TGS
        authenticator = new Authenticator(clientId, CLIENT_ADDR, command);

        try {
            authenticatorSerialized = Utils.serialize(authenticator);

            ResponseAuthenticationMessage tgt = mapUsers.get(clientId).getTGT();
            try {
                sendTGSRequest(socket, tgt.getEncryptedTGT(),
                        CryptoStuff.getInstance()
                                .encrypt(tgt.getGeneratedKey(),
                                        authenticatorSerialized),
                        command);
            } catch (InvalidAlgorithmParameterException | CryptoException e) {
                e.printStackTrace();
            }

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
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static CommandReturn processResponse(Wrapper wrapper, SecretKey sessionKey, String clientId, String command)
            throws RuntimeException, IOException, ClassNotFoundException, InvalidKeyException,
            InvalidAlgorithmParameterException, CryptoException {
        logger.info("Processing service response status");
        MessageStatus status = MessageStatus.fromCode(wrapper.getStatus());

        logger.info("Status: " + status);
        switch (status) {
            case OK, OK_NO_CONTENT:
                byte[] encryptedResponse = wrapper.getMessage();
                byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(sessionKey, encryptedResponse);
                return ((ResponseServiceMessage) Utils.deserialize(decryptedResponse)).getcommandReturn();
            case BAD_REQUEST:
                throw new RuntimeException("Command '" + command + "' is invalid");
            case UNAUTHORIZED:
                throw new RuntimeException("User '" + clientId + "' is not authorized to execute command '" + command
                        + "'. Authenticate user with command: login username password");
            case FORBIDDEN:
                throw new RuntimeException("User '" + clientId + "' is not authorized to execute command '" + command);
            case NOT_FOUND:
                throw new RuntimeException("File not found");
            case INTERNAL_SERVER_ERROR:
                throw new RuntimeException("Internal server error");
            case CONFLICT:
                throw new RuntimeException("File already exists");
            default:
                throw new RuntimeException("Unknown error");
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
                    Utils.serialize(requestMessage));

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

            byte[] requestMessageSerialized = Utils.serialize(requestMessage);

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
                    Utils.serialize(authenticator));

            RequestServiceMessage requestServiceMessage = new RequestServiceMessage(sgt.getSgt(),
                    encryptedAuthenticator, command);
            byte[] requestMessageSerialized = Utils.serialize(requestServiceMessage);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper wrapper = new Wrapper((byte) 6, requestMessageSerialized, UUID.randomUUID());

            // Send wrapper to dispatcher
            oos.writeObject(wrapper);
            oos.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static ResponseAuthenticationMessage processAuthResponse(SSLSocket socket, String clientId, String password)
            throws IncorrectPasswordException, UserNotFoundException {
        logger.severe("Processing auth response for client: " + clientId);
        ResponseAuthenticationMessage responseAuthenticationMessage = null;
        try {

            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            logger.info("Waiting for auth response");
            Wrapper wrapper = (Wrapper) ois.readObject();
            MessageStatus responseStatus = MessageStatus.fromCode(wrapper.getStatus());
            logger.info("Response status: " + responseStatus);
            switch (responseStatus) {
                case OK:
                    byte[] encryptedResponse = wrapper.getMessage();
                    try {
                        SecretKey clientKey = mapUsers.get(clientId).getKeyPassword();
                        byte[] descryptedResponse = CryptoStuff.getInstance().decrypt(clientKey, encryptedResponse);
                        responseAuthenticationMessage = (ResponseAuthenticationMessage) Utils
                                .deserialize(descryptedResponse);
                        return responseAuthenticationMessage;
                    } catch (CryptoException e) {
                        throw new IncorrectPasswordException("This password is incorrect.");
                    }
                case UNAUTHORIZED:
                    throw new UserNotFoundException(clientId);
                default:
                    break;
            }
        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return responseAuthenticationMessage;
    }

    public static ResponseTGSMessage processTGSResponse(SSLSocket socket, SecretKey key) {
        logger.severe("Processing TGS response");
        ResponseTGSMessage responseTGSMessage = null;
        try {
            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());

            logger.info("Waiting for TGS response");
            Wrapper wrapper = (Wrapper) ois.readObject();

            logger.info("Attempting to decrypt TGS response");
            // int responseStatus = wrapper.getStatus();
            byte[] encryptedResponse = wrapper.getMessage();
            byte[] decryptedResponse = CryptoStuff.getInstance().decrypt(key, encryptedResponse);

            logger.info("Attempting to deserialize TGS response");
            responseTGSMessage = (ResponseTGSMessage) Utils.deserialize(decryptedResponse);

            logger.info("Finished processing TGS response");
        } catch (Exception e) {
            e.printStackTrace();
        }
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

            responseServiceMessage = (ResponseServiceMessage) Utils.deserialize(decryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return responseServiceMessage;
    }

    private static String getProcess(byte[] payloadReceived, SecretKey key) {
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

        try (FileOutputStream fos = new FileOutputStream(downloadsDir)) {
            fos.write(CryptoStuff.getInstance().decrypt(key, payloadReceived));
            return "File downloaded successfully to: " + downloadsDir;
        } catch (Exception ex) {
            return "File wasn't successfully downloaded in dir: " + downloadsDir;
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
}