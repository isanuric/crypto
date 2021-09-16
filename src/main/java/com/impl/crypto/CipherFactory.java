package com.impl.crypto;

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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class CipherFactory {

    @Value("${keystore.path}")
    private String keystorePath;

    Cipher getCipher(int mode)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException {

        SecretKeySpec secretKeySpecification = new SecretKeySpec(getKey().getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(mode, secretKeySpecification, new IvParameterSpec(new byte[16]));
        return cipher;
    }

    Key getKey()
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException {

        InputStream keystoreStream = new FileInputStream(keystorePath);
        KeyStore keystore = KeyStore.getInstance("JCEKS");
        keystore.load(keystoreStream, "mystorepass".toCharArray());
        if (!keystore.containsAlias("jceksaes")) {
            throw new KeyStoreException("Alias for key not found");
        }
        return keystore.getKey("jceksaes", "asdDSA".toCharArray());
    }
}
