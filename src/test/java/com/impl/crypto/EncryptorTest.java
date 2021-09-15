package com.impl.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
// @TestPropertySource(locations="classpath:test.properties")
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

}