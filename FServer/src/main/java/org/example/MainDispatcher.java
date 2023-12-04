package org.example;

import com.sun.net.httpserver.*;
import org.example.utils.RequestMessage;
import org.example.utils.ResponseMessage;

import javax.net.ssl.*;
import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class MainDispatcher {

    public enum ModuleName {
        STORAGE,
        AUTHENTICATION,
        ACCESS_CONTROL
    }

    public static final String[] CONFPROTOCOLS      = {"TLSv1.2"};;
    public static final String[] CONFCIPHERSUITES   = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_PASSWORD    = "dispatcher_password";
    public static final String KEYSTORE_PATH        = "/app/keystore.jks";
    public static final String TRUSTSTORE_PASSWORD  = "dispatcher_truststore_password";
    public static final String TRUSTSTORE_PATH      = "/app/truststore.jks";
    public static final String TLS_VERSION          = "TLSv1.2";
    public static final int MY_PORT                 = 8080;

    private static String[] getHostAndPort(ModuleName moduleName) {
        switch (moduleName) {
            case STORAGE:
                return new String[]{"localhost", "8083"};
            case AUTHENTICATION:
                return new String[]{"localhost", "8081"};
            case ACCESS_CONTROL:
                return new String[]{"localhost", "8082"};
            default:
                throw new IllegalArgumentException("Invalid module name");
        }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl");
        initTLSServerSocket();


//        boolean runStorage = true;
//        boolean runAuthentication = true;
//        while(runStorage) {
//            try {
//                sendMessage(ModuleName.STORAGE);
//                runStorage = false;
//            } catch (Exception e) {
//                System.out.println("Failed to connect to storage server");
//            }
//        }
//        while(runAuthentication) {
//            try {
//                sendMessage(ModuleName.AUTHENTICATION);
//                runAuthentication = false;
//            } catch (Exception e) {
//                System.out.println("Failed to connect to auth server");
//            }
//        }
    }

    private static void initTLSServerSocket() {
        try {
            //Keystore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(MY_PORT);
            serverSocket.setUseClientMode(true);
            serverSocket.setEnabledProtocols(CONFPROTOCOLS);
            serverSocket.setEnabledCipherSuites(CONFCIPHERSUITES);

            System.out.println("Supported Ciphersuites: " + String.join(", ", serverSocket.getEnabledCipherSuites()));

            System.out.println("Server is listening on port 8080...");

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                Thread clientThread = new Thread(() -> handleRequest(clientSocket));
                clientThread.start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleRequest(SSLSocket clientSocket) {
        try {
            System.out.println("ENTROU handle request");
            // Communication logic with the client
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));

            String command;
            while((command = reader.readLine()) != null) {
                System.out.println("Received command: " + command);

                writer.write(command);
                writer.newLine();
                writer.flush();

//                String[] fullCommand = command.split("\\s+");
//
//                String commandName = fullCommand[0];
//
//                String username = "";
//                String path = "";
//                String file = "";
//                switch (commandName) {
//                    case "login":
//                        username = fullCommand[1];
//                        String password = fullCommand[2];
//
//                    case "ls":
//                        username = fullCommand[1];
//                        path = fullCommand[2];
//                    case "mkdir":
//                        username = fullCommand[1];
//                        path = fullCommand[2];
//                    case "put":
//                        username = fullCommand[1];
//                        file = fullCommand[2];
//                    case "get":
//                        username = fullCommand[1];
//                        file = fullCommand[2];
//                    case "cp":
//                        username = fullCommand[1];
//                        String file1 = fullCommand[2];
//                        String file2 = fullCommand[3];
//                    case "rm":
//                        username = fullCommand[1];
//                        file = fullCommand[2];
//                    case "file":
//                        file = fullCommand[1];
//                    default: break;
//                }
            }

            writer.close();
            reader.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void sendMessage(ModuleName moduleName) throws IOException {
        
        SSLSocket socket = initTLSClientSocket(moduleName);

        // Communication logic with the server
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

        // Example message to send
        String message = "Hello, Server!";
        writer.write(message);
        writer.newLine();
        writer.flush();

        // Read the server's response
        String response = reader.readLine();
        System.out.println("Server response: " + response);

        socket.close();

    }

    private static SSLSocket initTLSClientSocket(ModuleName module) {
        SSLSocket socket = null;
        try {
            String[] hostAndPort = getHostAndPort(module);

            //KeyStore
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(KEYSTORE_PATH), KEYSTORE_PASSWORD.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            //TrustStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD.toCharArray());
            Enumeration<String> aliases = trustStore.aliases();

//            while (aliases.hasMoreElements()) {
//                String alias = aliases.nextElement();
//                Certificate certificate = trustStore.getCertificate(alias);
//                System.out.println("Alias: " + alias);
//                System.out.println("Certificate: " + certificate.toString());
//            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            System.out.println(hostAndPort[0]);
            System.out.println(hostAndPort[1]);

            socket = (SSLSocket) sslSocketFactory.createSocket(hostAndPort[0], Integer.parseInt(hostAndPort[1]));

            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            // Start the handshake
            socket.startHandshake();

            SSLSession session = socket.getSession();

            System.out.println();
            System.out.println("Hum from my offer server decided to select\n");
            System.out.println("TLS protocol version: " + session.getProtocol());
            System.out.println("Ciphersuite: " + session.getCipherSuite());

        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return socket;
    }



}