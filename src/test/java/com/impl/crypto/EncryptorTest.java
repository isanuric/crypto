package com.impl.crypto;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class EncryptorTest {

    @Autowired
    Encryptor encryptor;

    @RepeatedTest(1)
    void encryptMessageKeystore() {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        byte[] encrypted;
            encrypted = encryptor.doCrypto(Cipher.ENCRYPT_MODE, plainText.getBytes(StandardCharsets.UTF_8));
            byte[] decrypted = encryptor.doCrypto(Cipher.DECRYPT_MODE, encrypted);
            assertEquals(plainText, new String(decrypted));
    }

    @Test
    void doCryptoFile() throws IOException, IllegalBlockSizeException, BadPaddingException,
                               KeyStoreException, NoSuchAlgorithmException {
        encryptor.doCryptoFile(Cipher.ENCRYPT_MODE,
                new File("src/main/resources/files/inputFile.txt"),
                new File("src/main/resources/files/outputFile.txt"));

        encryptor.doCryptoFile(Cipher.DECRYPT_MODE,
                new File("src/main/resources/files/outputFile.txt"),
                new File("src/main/resources/files/decrypted.txt"));

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypted.txt").read());
    }

}


