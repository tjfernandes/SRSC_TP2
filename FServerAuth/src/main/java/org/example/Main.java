package org.example;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.example.crypto.CryptoStuff;
import org.example.utils.RequestMessage;
import org.example.utils.ResponseMessage;
import org.example.utils.TicketGrantingTicket;

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
        final SSLServerSocket serverSocket = server();
        System.out.println("Server started on port " + MY_PORT);
        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket, serverSocket));
                clientThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket){
       try {
            // Communication logic with the request
            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            RequestMessage requestMessage;
            while ((requestMessage = (RequestMessage) objectInputStream.readObject()) != null) {
                Properties properties = loadProperties("/app/crypto-config.properties");
                String tgskey = properties.getProperty("TGS_AS_KEY");

                CryptoStuff cryptoStuff = CryptoStuff.getInstance();        

                KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
                kg.init(KEYSIZE);

                SecretKey generatedkey = kg.generateKey();
                
                SecureRandom secureRandom = new SecureRandom();
                int nonce = secureRandom.nextInt();

                TicketGrantingTicket tgt = new TicketGrantingTicket(requestMessage.getClientId(),requestMessage.getClientAddress() ,"ACCESS_CONTROL", nonce);
                
                ResponseMessage response = new ResponseMessage(cryptoStuff.encrypt(tgskey, tgt), generatedkey);
                
                objectOutputStream.writeUTF(response);
                objectOutputStream.flush();
            }

            objectOutputStream.close();
            objectInputStream.close();
            requestSocket.close();

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
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

    private static void echoRequest(SSLSocket requestSocket, SSLServerSocket serverSocket) {
        try {
            // Communication logic with the request
            BufferedReader reader = new BufferedReader(new InputStreamReader(requestSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(requestSocket.getOutputStream()));

            String message;
            while ((message = reader.readLine()) != null) {
                System.out.println("Received message: " + message);

                // Example response
                writer.write("Server Auth received your message: " + message);
                writer.newLine();
                writer.flush();
            }

            writer.close();
            reader.close();
            requestSocket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Properties loadProperties(String configFilePath) {
        Properties properties = new Properties();
        try (InputStream input = new FileInputStream(configFilePath)) {
            properties.load(input);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }
}