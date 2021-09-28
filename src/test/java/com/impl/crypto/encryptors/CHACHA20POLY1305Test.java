package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CHACHA20POLY1305Test extends BaseTest {

    public static final int REPEATES = 1;

    @Autowired
    private CHACHA20POLY1305 chacha20POLY1305;

    @RepeatedTest(REPEATES)
    void encryptMessageKeystore() throws Exception {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        final String encrypted = chacha20POLY1305.encrypt(plainText, keystorePassword);
        assertEquals(plainText, chacha20POLY1305.decrypt(encrypted, keystorePassword));
    }

    @RepeatedTest(REPEATES)
    void doCryptoFile() throws Exception {
        chacha20POLY1305.encryptFile(
                new File("src/main/resources/files/inputFile.txt"),
                keystorePassword);

        chacha20POLY1305.decryptFile(
                new File("src/main/resources/files/encrypt_inputFile.txt"),
                keystorePassword);

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypt_encrypt_inputFile.txt").read());
    }

}
