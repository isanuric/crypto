package com.impl.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class KeystoreFactory {

    @Value("${keystore.path}")
    private String keystorePath;

    Cipher getCipher(int mode)
            throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidKeyException,
                   NoSuchProviderException {
        SecretKeySpec secretKeySpecification = null;
        final byte[] key = getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5").getEncoded();
        secretKeySpecification = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        // Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(mode, secretKeySpecification);
        return cipher;
    }

    Key getKey(String password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException, NoSuchProviderException {

        InputStream keystoreStream = new FileInputStream(keystorePath);
        KeyStore keystore = null;
        keystore = KeyStore.getInstance("PKCS12", "SUN");

        keystore.load(keystoreStream, password.toCharArray());
        if (!keystore.containsAlias("test")) {
            throw new KeyStoreException("Alias for key not found");
        }
        return keystore.getKey("test", password.toCharArray());
    }
}

