package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class AESCBCTest extends BaseTest {

    @Autowired
    private AESCBC aesCbc;

    @RepeatedTest(1)
    void encryptMessageKeystore() {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        String encrypted = aesCbc.encrypt(plainText);
        String decrypted = aesCbc.decrypt(encrypted);
        assertEquals(plainText, decrypted);
    }

    @Test
    void doCryptoFile() throws Exception {
        aesCbc.doCryptoFile(Cipher.ENCRYPT_MODE,
                new File("src/main/resources/files/inputFile.txt"),
                new File("src/main/resources/files/outputFile.txt"));

        aesCbc.doCryptoFile(Cipher.DECRYPT_MODE,
                new File("src/main/resources/files/outputFile.txt"),
                new File("src/main/resources/files/decrypted.txt"));

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypted.txt").read());
    }

}



