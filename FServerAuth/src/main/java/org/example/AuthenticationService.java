package org.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
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

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.example.crypto.CryptoStuff;
import org.example.utils.RequestAuthenticationMessage;
import org.example.utils.ResponseAuthenticationMessage;
import org.example.utils.TicketGrantingTicket;
import org.example.utils.TimeoutUtils;
import org.example.utils.Wrapper;

public class AuthenticationService {

    public static final String[] CONFPROTOCOLS = { "TLSv1.2" };;
    public static final String[] CONFCIPHERSUITES = { "TLS_RSA_WITH_AES_256_CBC_SHA256" };
    public static final String KEYSTORE_PASSWORD = "authentication_password";
    public static final String KEYSTORE_PATH = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD = "authentication_truststore_password";
    public static final String TRUSTSTORE_PATH = "/app/truststore.jks";
    public static final String TLS_VERSION = "TLSv1.2";
    public static final int PORT_2_DISPATCHER = 8080;
    public static final int MY_PORT = 8081;

    public static final String ALGORITHM = "AES";
    public static final int KEYSIZE = 256;

    public static final String TGS_KEY_PATH = "/app/crypto-config.properties";
    public static final String TGS_KEY = "TGS_AS_KEY";

    public static final int OK = 200;
    public static final int UNAUTHORIZED = 401;
    private static SecretKey keyTGT = null;

    private static final long TIMEOUT = 10000;

    // Custom logger to print the timestamp in milliseconds
    private static final Logger logger = Logger.getLogger(AuthenticationService.class.getName());
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

    private static SecretKey dhKey;

    public static void main(String[] args) {
        // Set the logger level
        logger.setLevel(Level.INFO);

        Authentication authentication = new Authentication();
        dhKey = null;
        // Register a user
        // authentication.register("client", "12345");

        final SSLServerSocket serverSocket = server();
        System.out.println("Server started on port " + MY_PORT);

        // Load the Properties file
        Properties props = new Properties();
        try (FileInputStream input = new FileInputStream(TGS_KEY_PATH)) {
            props.load(input);
            keyTGT = CryptoStuff.getInstance().convertStringToSecretKey(props.getProperty(TGS_KEY));
            while (true) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                TimeoutUtils.runWithTimeout(() -> handleRequest(socket, authentication, props), TIMEOUT);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (TimeoutException e) {
            logger.warning("Connection timed out");
        }
    }

    private static void handleRequest(SSLSocket requestSocket, Authentication authentication, Properties props) {
        try {
            logger.severe("Handling request");
            // Create input and output streams for the socket
            ObjectInputStream ois = new ObjectInputStream(requestSocket.getInputStream());

            // Read the message from the client
            Wrapper wrapper = (Wrapper) ois.readObject();
            byte messageType = wrapper.getMessageType();

            // Handle the message
            switch (messageType) {
                case 0:
                    handleKeyExchange(requestSocket, authentication, props, wrapper);
                    break;
                case 1:
                    handleAuthentication(requestSocket, authentication, props, wrapper);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleKeyExchange(SSLSocket requestSocket, Authentication authentication, Properties props,
            Wrapper wrapper) {
        try {
            logger.severe("Handling key exchange");
            // Create input and output streams for the socket
            ObjectOutputStream oos = new ObjectOutputStream(requestSocket.getOutputStream());

            byte[] publicKeyBytes = wrapper.getMessage();

            // Generate DH parameters
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048); // Adjust the key size as needed
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Generate public key and send it back to the sender
            byte[] receiverPublicKeyBytes = keyPair.getPublic().getEncoded();
            Wrapper response = new Wrapper(wrapper.getMessageType(), receiverPublicKeyBytes, wrapper.getMessageId());
            oos.writeObject(response);
            oos.flush();

            // Generate public key from received bytes
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
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
            dhKey = new SecretKeySpec(derivedKey, "AES");
            logger.info("DH key: " + dhKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleAuthentication(SSLSocket requestSocket, Authentication authentication, Properties props,
            Wrapper wrapper) {
        try {
            logger.severe("Handling authentication");
            // Create input and output streams for the socket
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            // Read the message from the client
            byte[] decryptedMessage = CryptoStuff.getInstance().decrypt(dhKey, wrapper.getMessage());
            RequestAuthenticationMessage request = (RequestAuthenticationMessage) deserialize(decryptedMessage);
            UUID uuid = wrapper.getMessageId();

            // Generate a key for client/tgs communication
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEYSIZE);
            SecretKey generatedkey = kg.generateKey();

            // Create a TGT
            TicketGrantingTicket tgt = new TicketGrantingTicket(request.getClientId(), request.getClientAddress(),
                    request.getServiceId(), generatedkey);
            byte[] tgtBytes = serialize(tgt);

            // Key to encrypt response
            byte[] key = authentication.getUsernamePassword(request.getClientId());
            if (key == null) {
                objectOutputStream.writeObject(new Wrapper((byte) 1, null, uuid, UNAUTHORIZED));
                objectOutputStream.flush();
                return;
            }
            SecretKey secretKey = CryptoStuff.getInstance().convertByteArrayToSecretKey(key);

            // Encrypt TGT and send it to the client
            byte[] encryptedTGT = CryptoStuff.getInstance().encrypt(keyTGT, tgtBytes);
            byte[] responseBytes = serialize(new ResponseAuthenticationMessage(generatedkey, encryptedTGT));
            objectOutputStream.writeObject(
                    new Wrapper((byte) 1, CryptoStuff.getInstance().encrypt(secretKey, responseBytes), uuid, OK));
            objectOutputStream.flush();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

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
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
            serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

            return serverSocket;

        } catch (Exception e) {
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