package com.impl.crypto.symmetric;

import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CHACHA20Test extends BaseTest {

    @Autowired
    private CHACHA20 chacha20;

    @RepeatedTest(1)
    void doCrypto() throws Exception {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        final String encrypted = chacha20.encrypt(plainText, keystorePassword);
        assertEquals(plainText, chacha20.decrypt(encrypted, keystorePassword));
    }

    @RepeatedTest(1)
    void doCryptoFile() throws Exception {
        chacha20.encryptFile(
                new File("src/main/resources/files/inputFile.txt"),
                keystorePassword);

        chacha20.decryptFile(
                new File("src/main/resources/files/encrypt_inputFile.txt"),
                keystorePassword);

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypt_encrypt_inputFile.txt").read());
    }
}

