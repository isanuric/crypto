package com.impl.crypto.asymmetric;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.apache.tomcat.util.codec.binary.Base64.decodeBase64;
import static org.apache.tomcat.util.codec.binary.Base64.encodeBase64String;

@Service
public class RSA {

    @Value("${keystore.asymmetric.path}")
    private String keystoreAsymmetricPath;

    @Value("${keystore.asymmetric.password}")
    private String  keystoreAsymmetricPassword;

    @Value("${keystore.asymmetric.alias}")
    private String keystoreAsymmetricAlias;

    private Cipher cipher;
    private KeyStore keystore;

    public RSA() throws NoSuchPaddingException, NoSuchAlgorithmException, KeyStoreException {
        this.cipher = Cipher.getInstance("RSA");
        this.keystore = KeyStore.getInstance("PKCS12");
    }

    public String encrypt(String msg, String alias, String password)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException {
        PublicKey publicKey = getKeyPair(alias, password).getPublic();
        this.cipher.init(ENCRYPT_MODE, publicKey);
        return encodeBase64String(cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }

    public String decrypt(String msg, PrivateKey key)
            throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException,
                   BadPaddingException {
        this.cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(decodeBase64(msg)), StandardCharsets.UTF_8);
    }

    KeyPair getKeyPair(String password)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
                   UnrecoverableKeyException {
        return getKeyPair(keystoreAsymmetricAlias, password);
    }

    KeyPair getKeyPair(String alias, String password)
            throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
                   UnrecoverableKeyException {
        try (InputStream keystoreStream = new FileInputStream(keystoreAsymmetricPath)) {
            keystore.load(keystoreStream, password.toCharArray());
        }

        if (!keystore.containsAlias(alias)) {
            throw new KeyStoreException("Alias for key not found");
        }

        final Key key = keystore.getKey(alias, password.toCharArray());

        if (key instanceof PrivateKey) {
            PublicKey publicKey  = keystore.getCertificate(alias).getPublicKey();
            return new KeyPair(publicKey, (PrivateKey) key);
        }

        return null;
    }

}
