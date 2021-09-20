package com.impl.crypto;

public class CryptoException extends Throwable {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Exception e) {
        super(message, e);
    }
}
