package com.impl.crypto.asymmetric;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
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

    KeyFactoryAsymmetric keyFactoryAsymmetric;
    private Cipher cipher;

    public RSA(KeyFactoryAsymmetric keyFactoryAsymmetric) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.keyFactoryAsymmetric = keyFactoryAsymmetric;
        this.cipher = Cipher.getInstance("RSA");
    }

    public String encrypt(String plainText, String alias, String password)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException {
        PublicKey publicKey = this.keyFactoryAsymmetric.getKeyPair(alias, password).getPublic();
        this.cipher.init(ENCRYPT_MODE, publicKey);
        return encodeBase64String(cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8)));
    }

    public String decrypt(String cipherText, String alias, String password)
            throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException {
        PrivateKey privateKey = this.keyFactoryAsymmetric.getKeyPair(alias, password).getPrivate();
        this.cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(decodeBase64(cipherText)), StandardCharsets.UTF_8);
    }

}

