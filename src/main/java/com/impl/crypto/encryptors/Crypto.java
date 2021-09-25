package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;

@Service
public class Crypto {

    enum Transition {
        AES_GCM ("AES/GCM/NoPadding"),
        AES_CBC ("AES/CBC/PKCS5Padding");

        private String value;
        Transition(String value) {
            this.value = value;
        }
    }

    private final KeystoreFactory keystoreFactory;

    public Crypto(KeystoreFactory keystoreFactory) {
        this.keystoreFactory = keystoreFactory;
    }

    byte[] doDecryption(byte[] encrypted, final byte[] iv, String password, Transition transition)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, KeyStoreException,
                   CertificateException, UnrecoverableKeyException, NoSuchProviderException,
                   InvalidKeyException, InvalidAlgorithmParameterException,
                   IllegalBlockSizeException, BadPaddingException {

        AlgorithmParameterSpec parameterSpec = null;
        switch (transition) {
            case AES_GCM:
                parameterSpec = new GCMParameterSpec(16 * 8, iv);
                break;
            case AES_CBC:
                parameterSpec = new IvParameterSpec(iv);
                break;
            default:
        }

        Cipher cipher = Cipher.getInstance(transition.value);
        cipher.init(Cipher.DECRYPT_MODE, keystoreFactory.getKey(password), parameterSpec);
        return cipher.doFinal(encrypted);
    }
}
