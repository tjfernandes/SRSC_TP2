package org.example;

import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.SecretKey;
import javax.net.ssl.*;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.utils.Authenticator;
import org.example.utils.Command;
import org.example.utils.CommandReturn;
import org.example.utils.RequestServiceMessage;
import org.example.utils.ResponseServiceMessage;
import org.example.utils.ServiceGrantingTicket;
import org.example.utils.TimeoutUtils;
import org.example.utils.Wrapper;
import org.example.utils.Pair;

public class StorageService {

    public static final String KEYSTORE_PASSWORD = "storage_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "storage_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8080;
    public static final int MY_PORT = 8083;
    public static final String STORAGE_TGS_KEY_PATH = "/app/crypto-config.properties";

    public static final String ALGORITHM = "AES";
    public static final int KEYSIZE = 256;

    private static final long TIMEOUT = 10000;

    enum CommandEnum {
        GET, PUT, RM, LS, MKDIR, CP, FILE
    }

    private static final Properties properties = new Properties();

    static {
        try (InputStream input = StorageService.class.getClassLoader()
                .getResourceAsStream("/app/tls-config.properties")) {
            properties.load(input);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static final String[] TLS_PROT_ENF = properties.getProperty("TLS-PROT-ENF").split(",");
    public static final String[] CIPHERSUITES = properties.getProperty("CIPHERSUITES").split(",");
    public static final String TLS_AUTH = properties.getProperty("TLS-AUTH");

    // Custom logger to print the timestamp in milliseconds
    public static final Logger logger = Logger.getLogger(StorageService.class.getName());
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

    public static void main(String[] args) {

        // Set logger level
        logger.setLevel(Level.SEVERE);

        final SSLServerSocket serverSocket = server();
        FsManager fsManager = new FsManager();
        CryptoStuff crypto = CryptoStuff.getInstance();

        // loading the key from the properties file
        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(STORAGE_TGS_KEY_PATH)) {
            props.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // converting from String to SecretKey
        SecretKey key = crypto.convertStringToSecretKey(props.getProperty("STORAGE_TGS_KEY"));
        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                TimeoutUtils.runWithTimeout(() -> handleRequest(clientSocket, serverSocket, fsManager, crypto, key),
                        TIMEOUT);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (TimeoutException e) {
                logger.warning("Connection timed out.");
            }
        }

    }

    // Process the command and returns the payload and the code
    public static Pair<CommandReturn, Integer> processCommand(String clientId, Command command, FsManager fsManager,
            CommandEnum commandEnum) {

        byte[] payload = null;
        int code = 0;
        Pair<byte[], Integer> pair;

        switch (commandEnum) {
            case GET:
                pair = fsManager.getCommand(clientId, command.getPath());
                payload = pair.first;
                code = pair.second;
                break;
            case PUT:
                code = fsManager.putCommand(clientId, command.getPath(), command.getPayload());
                break;
            case RM:
                code = fsManager.rmCommand(clientId, command.getPath());
                break;
            case LS:
                pair = fsManager.lsCommand(clientId, command.getPath());
                code = pair.second;
                payload = pair.first;
                break;
            case MKDIR:
                code = fsManager.mkdirCommand(clientId, command.getPath());
                break;
            case CP:
                code = fsManager.cpCommand(clientId, command.getPath(), command.getCpToPath());
                break;
            case FILE:
                pair = fsManager.getCommand(clientId, command.getPath());
                payload = pair.first;
                code = pair.second;
                break;
        }
        if (payload == null)
            return new Pair<>(new CommandReturn(command), code);
        return new Pair<>(new CommandReturn(command, payload), code);

    }

    // Handle the request
    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket, FsManager fsManager,
            CryptoStuff crypto, SecretKey key) {
        try {
            // Creating the streams
            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            // Reading the RequestMessage
            Wrapper wrapper = (Wrapper) objectInputStream.readObject();
            RequestServiceMessage requestServiceMessage = (RequestServiceMessage) deserialize(wrapper.getMessage());
            byte messageType = wrapper.getMessageType();
            UUID messageId = wrapper.getMessageId();

            // Processing the RequestMessage
            Pair<byte[], Integer> encryptedResponse = processRequest(requestServiceMessage, fsManager, crypto, key);

            // Create a new Wrapper object with the byte array
            Wrapper responseWrapper = new Wrapper(messageType, encryptedResponse.first, messageId,
                    encryptedResponse.second);

            // Sending the ResponseMessage
            objectOutputStream.writeObject(responseWrapper);
            objectOutputStream.flush();

        } catch (IOException | ClassNotFoundException | InvalidAlgorithmParameterException | CryptoException e) {
            e.printStackTrace();
        }
    }

    // Process the request for a single request
    private static Pair<byte[], Integer> processRequest(RequestServiceMessage requestServiceMessage,
            FsManager fsManager,
            CryptoStuff crypto, SecretKey key)
            throws IOException, ClassNotFoundException, InvalidAlgorithmParameterException, CryptoException {

        // Decrypting the Service Granting Ticket
        byte[] encryptedsgt = requestServiceMessage.getEncryptedSGT();
        byte[] sgtBytes = crypto.decrypt(key, encryptedsgt);
        ServiceGrantingTicket sgt = (ServiceGrantingTicket) deserialize(sgtBytes);

        // Decrypting the Authenticator
        byte[] encryptedAuth = requestServiceMessage.getAuthenticator();
        byte[] authBytes = crypto.decrypt(sgt.getKey(), encryptedAuth);
        Authenticator authenticator = (Authenticator) deserialize(authBytes);

        LocalDateTime returnTime = authenticator.getTimestamp().plusNanos(1);
        Command command = sgt.getCommand();
        // Checking if the Authenticator is valid
        if (!authenticator.isValid(sgt.getClientId(), sgt.getClientAddress())) {
            return new Pair<>(crypto.encrypt(sgt.getKey(), serialize(new ResponseServiceMessage(
                    new CommandReturn(command), returnTime))), 400);
        }

        // Checking if the command is valid
        if (!command.isValid()) {
            return new Pair<>(crypto.encrypt(sgt.getKey(), serialize(new ResponseServiceMessage(
                    new CommandReturn(command), returnTime))), 400);
        }

        String userId = sgt.getClientId();

        Pair<CommandReturn, Integer> commandReturn = processCommand(userId, command, fsManager,
                CommandEnum.valueOf(command.getCommand().toUpperCase()));

        return new Pair<>(
                crypto.encrypt(sgt.getKey(), serialize(new ResponseServiceMessage(commandReturn.first, returnTime))),
                commandReturn.second);
    }

    // Create the server socket
    private static SSLServerSocket server() {
        try {
            // KeyStore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            // TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MY_PORT);
            serverSocket.setEnabledProtocols(TLS_PROT_ENF);
            serverSocket.setEnabledCipherSuites(CIPHERSUITES);
            boolean needAuth = TLS_AUTH.equals("MUTUAL");
            serverSocket.setNeedClientAuth(needAuth);

            return serverSocket;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /* ---- Auxiliary method ---- */

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
