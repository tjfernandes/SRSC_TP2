package org.example;

import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.*;

import org.example.utils.Command;
import org.example.utils.RequestMessage;
import org.example.utils.ResponseMessage;

public class Main {

    public static final String[] CONFPROTOCOLS      = {"TLSv1.2"};;
    public static final String[] CONFCIPHERSUITES   = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_PASSWORD    = "storage_password";
    public static final String KEYSTORE_PATH        = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD  = "storage_truststore_password";
    public static final String TRUSTSTORE_PATH      = "/app/truststore.jks";
    public static final String TLS_VERSION          = "TLSv1.2";
    public static final int PORT_2_DISPATCHER       = 8080;
    public static final int MY_PORT                 = 8083;

    public static final String ALGORITHM            = "AES";
    public static final int KEYSIZE                 = 256;


    public static void main(String[] args) {
        final SSLServerSocket serverSocket = server();
        FsManager fsManager = new FsManager();
        System.out.println("Server started on port " + MY_PORT);
        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket, serverSocket, fsManager));
                clientThread.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void handleRequest(SSLSocket requestSocket, SSLServerSocket serverSocket,FsManager fsManager){
       try {

            ObjectInputStream objectInputStream = new ObjectInputStream(requestSocket.getInputStream());
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(requestSocket.getOutputStream());

            RequestMessage requestMessage;
            while ((requestMessage = (RequestMessage) objectInputStream.readObject()) != null) {
                ResponseMessage response = null;
                
                Command command = requestMessage.getCommand();
                switch (command.getCommand()) {
                    case "GET":
                        byte[] payload = fsManager.getCommand(command.getPath());
                        response = new ResponseMessage(payload, 204);
                        break;
                    case "PUT":
                        fsManager.putCommand(command.getPath(),command.getPayload());
                        response = new ResponseMessage(200);
                        break;
                    case "RM":
                        fsManager.rmCommand(command.getPath());
                        response = new ResponseMessage(200);
                        break;
                    case "LS":
                        fsManager.lsCommand(command.getPath());
                        response = new ResponseMessage(204);
                        break;
                    case "MKDIR":
                        fsManager.mkdirCommand(command.getPath());
                        response = new ResponseMessage(200);
                        break;
                    case "CP":
                        fsManager.cpCommand(command.getPath(),command.getCpToPath());
                        response = new ResponseMessage(200);
                        break;
                    default:
                        response = new ResponseMessage(400);
                        break;
                }
                objectOutputStream.writeObject(response);
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
}
