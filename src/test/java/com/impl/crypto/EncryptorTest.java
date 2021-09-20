package com.impl.crypto;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class EncryptorTest {

    @Autowired
    Encryptor encryptor;

    @Disabled
    @Test
    void encryptMessage()
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                   BadPaddingException, InvalidKeyException {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        byte[] key = "KEY1234567890qwe".getBytes();
        byte[] encrypted = encryptor.encryptMessage(plainText.getBytes(), key);
        byte[] decrypted = encryptor.decryptMessage(encrypted, key);
        assertEquals(plainText, new String(decrypted));
    }

    @RepeatedTest(1)
    void encryptMessageKeystore() {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        byte[] encrypted = new byte[0];
        try {
            encrypted = encryptor.doCrypto(Cipher.ENCRYPT_MODE, plainText.getBytes(StandardCharsets.UTF_8));
            byte[] decrypted = encryptor.doCrypto(Cipher.DECRYPT_MODE, encrypted);
            assertEquals(plainText, new String(decrypted));

        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    @Test
    void doCryptoFile() throws IOException, UnrecoverableKeyException, IllegalBlockSizeException,
                               NoSuchPaddingException, CertificateException, BadPaddingException,
                               KeyStoreException, NoSuchAlgorithmException, InvalidKeyException,
                               NoSuchProviderException {
        encryptor.doCryptoFile(Cipher.ENCRYPT_MODE,
                new File("src/main/resources/files/inputFile.txt"),
                new File("src/main/resources/files/outputFile.txt"));

        encryptor.doCryptoFile(Cipher.DECRYPT_MODE,
                new File("src/main/resources/files/outputFile.txt"),
                new File("src/main/resources/files/decrypted.txt"));

        assertEquals(
                new FileInputStream(new File("src/main/resources/files/inputFile.txt")).read(),
                new FileInputStream(new File("src/main/resources/files/decrypted.txt")).read());
    }

}

