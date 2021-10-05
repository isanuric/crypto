package com.impl.crypto.asymmetric;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;

@Service
public class RSAECB {

    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    String doCrypto(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                                             IllegalBlockSizeException, BadPaddingException {

        KeyPair keyPair = getKeyPair();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        var cipherTextBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        String cipherText = getEncoder().encodeToString(cipherTextBytes);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        var decryptedCipherTextBytes = cipher.doFinal(getDecoder().decode(cipherText));
        return new String(decryptedCipherTextBytes, StandardCharsets.UTF_8);

    }

    private KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        return keyPairGenerator.generateKeyPair();
    }
}
