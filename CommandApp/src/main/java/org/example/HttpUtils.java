package org.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class HttpUtils {

    public static String makeHttpRequest(String urlString, String requestType, String jwtToken) throws IOException {
        StringBuilder response = new StringBuilder();

        try {
            HttpURLConnection connection = getHttpURLConnection(urlString, requestType, jwtToken);

            // Get the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }
            }

            // Close the connection
            connection.disconnect();
        } catch (IOException e) {
            throw new IOException(e.getMessage());
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        return response.toString();
    }

    private static HttpURLConnection getHttpURLConnection(String urlString, String requestType, String jwtToken) throws URISyntaxException, IOException {
        URI uri = new URI(urlString);
        URL url = uri.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        // Set up the request method, timeouts, etc.
        connection.setRequestMethod(requestType);
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        // Set the Authorization header with the JWT token
        if (jwtToken != null) connection.setRequestProperty("Authorization", "Bearer " + jwtToken);

        return connection;
    }

}
