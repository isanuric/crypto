package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CHACHATest extends BaseTest {

    @Autowired
    private CHACHA chacha;

    @RepeatedTest(1)
    void encryptMessageKeystore() throws Exception {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        final String encrypted = chacha.encrypt(plainText, keystorePassword);
        assertEquals(plainText, chacha.decrypt(encrypted, keystorePassword));
    }
}
