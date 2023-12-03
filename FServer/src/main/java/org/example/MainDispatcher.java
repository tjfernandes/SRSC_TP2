package org.example;

import com.sun.net.httpserver.*;

import okhttp3.Request;

import javax.net.ssl.*;

import org.example.utils.RequestMessage;

import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Map;

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
                return new String[]{"172.17.0.1", "8083"};
            case AUTHENTICATION:
                return new String[]{"172.17.0.1", "8081"};
            case ACCESS_CONTROL:
                return new String[]{"172.17.0.1", "8082"};
            default:
                throw new IllegalArgumentException("Invalid module name");
        }
    }

    public static void main(String[] args) throws Exception {
        boolean runStorage = true;
        boolean runAuthentication = true;
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        /*while(runStorage) {
            try {
                sendMessage(ModuleName.STORAGE);
                runStorage = false;
            } catch (Exception e) {
                System.out.println("Failed to connect to storage server");
            }
        }*/
        while(runAuthentication) {
            try {
                //sendMessage(ModuleName.AUTHENTICATION);
                runAuthentication = false;
            } catch (Exception e) {
                System.out.println("Failed to connect to auth server");
            }
        }  
        
        RequestMessage requestMessage = new RequestMessage("client1", "service1", 1234);

        SSLSocket socket = initTLSSocket(ModuleName.AUTHENTICATION);

        // Communication logic with the server
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());

        // Send the message
        objectOutputStream.writeObject(requestMessage);
        objectOutputStream.flush();

        // Get the input stream
BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        // Read the server's response
        String response = reader.readLine();
        System.out.println("Server response: " + response);


        socket.close();
    }

    private static void sendMessage(ModuleName moduleName) throws IOException {
        
        SSLSocket socket = initTLSSocket(moduleName);

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

    static class LoginHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            Map<String, String> queryParams = parseQueryParams(query);

            String username = queryParams.get("username");
            String password = queryParams.get("password");


            String response = "Username: " + username + "\nPassword: " + password;
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private static SSLSocket initTLSSocket(ModuleName module) {
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

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = trustStore.getCertificate(alias);
                System.out.println("Alias: " + alias);
                System.out.println("Certificate: " + certificate.toString());
            }
            
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            System.out.println(hostAndPort[0]);
            System.out.println(hostAndPort[1]);
            
            socket = (SSLSocket) sslSocketFactory.createSocket(hostAndPort[0], Integer.parseInt(hostAndPort[1]));

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

    static class ListHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the list page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class MakeDirHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the make dir page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class PutHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the put page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class GetHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the get page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class CopyHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the copy page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class RemoveHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the remove page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class FileHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "This is the file page!";
            exchange.sendResponseHeaders(200, response.length());
            OutputStream os = exchange.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    private static Map<String, String> parseQueryParams(String query) {
        return java.util.Arrays.stream(query.split("&"))
                .map(s -> s.split("="))
                .collect(java.util.stream.Collectors.toMap(a -> a[0], a -> a.length > 1 ? a[1] : ""));
    }

}