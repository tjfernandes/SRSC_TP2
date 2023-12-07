package org.example.utils;

public enum MessageStatus {

    OK(200),
    OK_NO_CONTENT(204),
    BAD_REQUEST(400),
    UNAUTHORIZED(401),
    FORBIDDEN(403),
    NOT_FOUND(404),
    INTERNAL_SERVER_ERROR(500);

    private final Integer code;

    MessageStatus(Integer code) {
        this.code = code;
    }

    public Integer getCode() {
        return code;
    }
}
