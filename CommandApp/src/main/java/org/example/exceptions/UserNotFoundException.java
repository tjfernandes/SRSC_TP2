package org.example.exceptions;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String username) {
        super(String.format("User '%s' is not authenticated", username));
    }
}
