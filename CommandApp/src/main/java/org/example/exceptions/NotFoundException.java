package org.example.exceptions;

public class NotFoundException extends RuntimeException {
    public NotFoundException() {
        super("File not found");
    }

}
