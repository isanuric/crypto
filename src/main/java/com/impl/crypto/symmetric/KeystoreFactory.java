package com.impl.crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class KeystoreFactory {

    @Value("${keystore.p12.path}")
    private String keystorePath;

    @Value("${keystore.chacha.path}")
    private String keystoreChachaPath;

    Key getKeyPKCS12(String password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException {

        try (InputStream keystoreStream = new FileInputStream(keystorePath)) {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(keystoreStream, password.toCharArray());

            final String alias = "test00";
            if (!keystore.containsAlias(alias)) {
                throw new KeyStoreException("Alias for key not found");
            }
            return keystore.getKey(alias, password.toCharArray());
        }
    }

    SecretKey getKeyBKS(String password)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException {

        Security.insertProviderAt(new BouncyCastleProvider(), 13);
        try (InputStream keystoreStream = new FileInputStream(keystoreChachaPath)) {
            KeyStore keystore = KeyStore.getInstance("BKS");
            keystore.load(keystoreStream, password.toCharArray());

            final String alias = "chacha";
            if (!keystore.containsAlias(alias)) {
                throw new KeyStoreException("Alias for key not found");
            }
            return (SecretKey) keystore.getKey(alias, "qayXSW321".toCharArray());
        }
    }
}

