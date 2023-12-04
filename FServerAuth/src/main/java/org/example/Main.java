package org.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.example.crypto.CryptoException;
import org.example.crypto.CryptoStuff;
import org.example.utils.RequestMessage;
import org.example.utils.ResponseMessage;
import org.example.utils.TicketGrantingTicket;
import org.example.utils.Wrapper;

public class Main {

    public static final String[] CONFPROTOCOLS      = {"TLSv1.2"};;
    public static final String[] CONFCIPHERSUITES   = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_PASSWORD    = "authentication_password";
    public static final String KEYSTORE_PATH        = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD  = "authentication_truststore_password";
    public static final String TRUSTSTORE_PATH      = "/app/truststore.jks";
    public static final String TLS_VERSION          = "TLSv1.2";
    public static final int PORT_2_DISPATCHER       = 8080;
    public static final int MY_PORT                 = 8081;

    public static final String ALGORITHM            = "AES";
    public static final int KEYSIZE                 = 256;


    public static void main(String[] args) {
        Authentication authentication = new Authentication();
        final SSLServerSocket serverSocket = server();
        System.out.println("Server started on port " + MY_PORT);
        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket, serverSocket, authentication));
                clientThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket, Authentication authentication) {
       try {

            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            Wrapper wrapper;
            while ((wrapper = (Wrapper) objectInputStream.readObject()) != null) {
                RequestMessage requestMessage = null;
                byte messageType = wrapper.getMessageType();
                byte[] serializedMessage = wrapper.getMessage();

                try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(serializedMessage);
                    ObjectInputStream inputStream = new ObjectInputStream(byteArrayInputStream)) {
                    requestMessage = (RequestMessage) inputStream.readObject();
                } catch (IOException | ClassNotFoundException e) {
                    // Handle any exceptions that occur during deserialization
                    e.printStackTrace();
                }
                
                KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
                kg.init(KEYSIZE);

                SecretKey generatedkey = kg.generateKey();
                
                TicketGrantingTicket tgt = new TicketGrantingTicket(requestMessage.getClientId(),requestMessage.getClientAddress() ,requestMessage.getServiceId(), generatedkey);
                byte[] tgtBytes = null;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                ObjectOutputStream outStream = null;
                try {
                    outStream = new ObjectOutputStream(bos);
                    outStream.writeObject(tgt);
                    outStream.flush();
                    tgtBytes = bos.toByteArray();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        bos.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }

                String key = authentication.getUsernamePassword(requestMessage.getClientId());
                SecretKey secretKey = CryptoStuff.getInstance().convertStringToSecretKeyto(key);

                byte[] encryptedTGT = null;
                try {
                    encryptedTGT = CryptoStuff.getInstance().encrypt(secretKey, tgtBytes);
                } catch (InvalidAlgorithmParameterException | CryptoException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                ResponseMessage response = new ResponseMessage(generatedkey, encryptedTGT);

                byte[] responseBytes = null;
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    outStream = new ObjectOutputStream(baos);
                    outStream.writeObject(response);
                    outStream.flush();
                    responseBytes = baos.toByteArray();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        baos.close();
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
                
                try {
                    objectOutputStream.writeObject(new Wrapper(messageType, CryptoStuff.getInstance().encrypt(generatedkey, responseBytes)));
                } catch (InvalidAlgorithmParameterException | CryptoException e) {
                    e.printStackTrace();
                }

                objectOutputStream.flush();
            }

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
    }


    private static SSLServerSocket server() {

        try {
            //KeyStore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());
            
            //TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
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
}