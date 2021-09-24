package com.impl.crypto.encryptors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class KeystoreFactory {

    @Value("${keystore.path}")
    private String keystorePath;

    Cipher getCipher(int cipherMode) {
        SecretKeySpec secretKeySpecification;
        final byte[] key;
        Cipher cipher = null;
        try {
            key = getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5").getEncoded();
            secretKeySpecification = new SecretKeySpec(key, "AES");
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Save the IV bytes or send it in plaintext with the encrypted data so you can decrypt the data later
            byte[] iv = new byte[16];
            if (cipherMode == 1) {
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(iv);
            }
            cipher.init(cipherMode, secretKeySpecification, new IvParameterSpec(iv));

        } catch (NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException |
                NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException |
                IOException | KeyStoreException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        return cipher;
    }

    Key getKey(String password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException, NoSuchProviderException {
        KeyStore keystore;
        try (InputStream keystoreStream = new FileInputStream(keystorePath)) {
            keystore = KeyStore.getInstance("PKCS12", "SUN");
            keystore.load(keystoreStream, password.toCharArray());
        }

        final String alias = "test00";
        if (!keystore.containsAlias(alias)) {
            throw new KeyStoreException("Alias for key not found");
        }

        return keystore.getKey(alias, password.toCharArray());
    }
}


