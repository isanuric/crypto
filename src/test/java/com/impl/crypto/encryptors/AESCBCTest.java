package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class AESCBCTest extends BaseTest {

    @Autowired
    private AESCBC aesCbc;

    @RepeatedTest(1)
    void encryptMessageKeystore()
            throws InvalidAlgorithmParameterException, UnrecoverableKeyException,
                   NoSuchPaddingException, IllegalBlockSizeException, CertificateException,
                   IOException, KeyStoreException, NoSuchAlgorithmException, BadPaddingException,
                   InvalidKeyException {

        String plainText = "Initializing Spring embedded WebApplicationContext";
        String encrypted = aesCbc.encrypt(plainText, keystorePassword);
        String decrypted = aesCbc.decrypt(encrypted, keystorePassword);
        assertEquals(plainText, decrypted);
    }

    @RepeatedTest(1)
    void doCryptoFile() throws Exception {
        aesCbc.encryptFile(
                new File("src/main/resources/files/inputFile.txt"),
                keystorePassword);

        aesCbc.decryptFile(
                new File("src/main/resources/files/encrypt_inputFile.txt"),
                keystorePassword);

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypt_encrypt_inputFile.txt").read());
    }

}





