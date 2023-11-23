package org.example;

import java.util.prefs.Preferences;

/**
 * Token Management
 */
public class JwtTokenUtils {

    private static final String JWT_PREF_TOKEN = "jwt_token";

    public static String extractJwtToken(String response) {
        // Implement logic to extract the JWT token from the response
        // This depends on the format of your authentication API response
        // For example, if the response is a JSON object, you might use a JSON parser
        // to extract the token field.
        return "your_extracted_jwt_token";
    }


    public static void storeToken(String jwtToken) {
        Preferences prefs = Preferences.userNodeForPackage(RemoteFileSystemApp.class);
        prefs.put(JWT_PREF_TOKEN, jwtToken);
    }

    public static String getStoredToken() {
        Preferences prefs = Preferences.userNodeForPackage(RemoteFileSystemApp.class);
        return prefs.get(JWT_PREF_TOKEN, null);
    }
}
