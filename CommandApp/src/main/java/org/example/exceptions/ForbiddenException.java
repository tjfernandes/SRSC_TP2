package org.example.exceptions;

public class ForbiddenException extends RuntimeException {
    public ForbiddenException() {
        super("User not authorized to access this resource");
    }
}
