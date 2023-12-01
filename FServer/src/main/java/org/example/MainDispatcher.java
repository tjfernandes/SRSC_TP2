package org.example;

import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.Map;

public class MainDispatcher {

    public static void main(String[] args) throws Exception {

        int port = 8080;

        HttpsServer server = createHttpsServer(port);

        //define endpoints
        server.createContext("/api/login", new LoginHandler());
        server.createContext("/api/ls", new ListHandler());
        server.createContext("/api/mkdir", new MakeDirHandler());
        server.createContext("/api/put", new PutHandler());
        server.createContext("/api/get", new GetHandler());
        server.createContext("/api/cp", new CopyHandler());
        server.createContext("/api/rm", new RemoveHandler());
        server.createContext("/api/file", new FileHandler());

        server.setExecutor(null);
        server.start();

        System.out.println("Server started on port " + port);

        try {
            // Load your keystore and truststore here

            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (InputStream is = MainDispatcher.class.getResourceAsStream("/truststore")) {
                trustStore.load(is, "your_client_truststore_password".toCharArray());
            }

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);


            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket("localhost", 8084);

            socket.startHandshake();

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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static HttpsServer createHttpsServer(int port) throws Exception {
        // Load keystore
        char[] keyStorePassword = "tftftf".toCharArray();
        char[] keyPassword = "tftftfpass".toCharArray();

        InputStream keyStoreIS = MainDispatcher.class.getClassLoader().getResourceAsStream("tfselfcertificate.jks");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStoreIS, keyStorePassword);

        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, keyStorePassword);

        final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(keyStore);

        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);


        HttpsServer server = HttpsServer.create(new InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));

        return server;

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

    private static void requestToServer(String serverName, int port) {
        try {
            // Load your keystore and truststore here
            System.setProperty("javax.net.ssl.keyStore", "client-keystore.jks");
            System.setProperty("javax.net.ssl.keyStorePassword", "your_keystore_password");
            System.setProperty("javax.net.ssl.trustStore", "trustedstore");
            System.setProperty("javax.net.ssl.trustStorePassword", "your_truststore_password");

            SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket("localhost", 8084);

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
        } catch (IOException e) {
            e.printStackTrace();
        }
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