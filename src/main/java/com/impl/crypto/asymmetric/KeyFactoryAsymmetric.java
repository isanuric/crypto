package com.impl.crypto.asymmetric;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Component
public class KeyFactoryAsymmetric {


    @Value("${keystore.asymmetric.alias}")
    private String keystoreAsymmetricAlias;

    @Value("${keystore.asymmetric.path}")
    private String keystoreAsymmetricPath;

    private KeyStore keyStore;

    public KeyFactoryAsymmetric() throws KeyStoreException {
        this.keyStore = KeyStore.getInstance("PKCS12");
    }

    KeyPair getKeyPair(String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException {
        return getKeyPair(keystoreAsymmetricAlias, password);
    }

    KeyPair getKeyPair(String alias, String password)
            throws IOException, KeyStoreException, NoSuchAlgorithmException,
                   CertificateException, UnrecoverableKeyException {
        try (InputStream keystoreStream = new FileInputStream(keystoreAsymmetricPath)) {
            this.keyStore.load(keystoreStream, password.toCharArray());
        }

        if (!this.keyStore.containsAlias(alias)) {
            throw new KeyStoreException("Alias for key not found");
        }

        final Key key = this.keyStore.getKey(alias, password.toCharArray());

        if (key instanceof PrivateKey) {
            PublicKey publicKey  = this.keyStore.getCertificate(alias).getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }

        return null;
    }
}
