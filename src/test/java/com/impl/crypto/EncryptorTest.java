package com.impl.crypto;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class EncryptorTest {

    @Autowired
    Encryptor encryptor;

    @Test
    void encryptMessage() throws NoSuchPaddingException, IllegalBlockSizeException,
                                 NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        byte[] key = "KEY1234567890qwe".getBytes();
        byte[] encrypted = encryptor.encryptMessage(plainText.getBytes(), key);
        byte[] decrypted = encryptor.decryptMessage(encrypted, key);
        assertEquals(plainText, new String(decrypted));
    }

    @RepeatedTest(2)
    void encryptMessageKeystore()
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                   BadPaddingException, InvalidKeyException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException,
                   InvalidAlgorithmParameterException {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        byte[] encrypted = encryptor.encryptMessageKeystore(plainText);
        byte[] decrypted = encryptor.decryptMessageKeystore(encrypted);
        assertEquals(plainText, new String(decrypted));
    }

}
