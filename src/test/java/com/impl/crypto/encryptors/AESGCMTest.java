package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESGCMTest extends BaseTest {

    @Autowired
    private AESGCM aesGcm;

    @RepeatedTest(1)
    void encryptMessageKeystore() throws Exception {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        final String encrypted = aesGcm.encrypt(plainText, keystorePassword);
        assertEquals(plainText, aesGcm.decrypt(encrypted, keystorePassword));
    }

    @Test
    void doCryptoFile() throws Exception {
        aesGcm.encryptFile(new File("src/main/resources/files/inputFile.txt"), keystorePassword);
        aesGcm.decryptFile(new File("src/main/resources/files/encrypted_inputFile.txt"), keystorePassword);

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypted_encrypted_inputFile.txt").read());
    }

}

