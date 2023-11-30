package org.example;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class HttpUtils {

    static {
        // Create a custom trust manager that trusts all certificates
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String makeHttpRequest(String urlString, String requestType, String jwtToken) throws IOException {
        StringBuilder response = new StringBuilder();

        try {
            URL serverURL = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) serverURL.openConnection();

            // Set up the request method, timeouts, etc. BEFORE connecting
            connection.setRequestMethod(requestType);
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            // Set the Authorization header with the JWT token
            if (jwtToken != null) {
                connection.setRequestProperty("Authorization", "Bearer " + jwtToken);
            }

            // Get the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }
            }

            // Close the connection
            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return response.toString();
    }
}
