package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static java.util.Base64.getDecoder;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class AESGCM {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    private KeystoreFactory keystoreFactory;
    private IvUtils ivUtils;

    public AESGCM(KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String plaintext)
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException, NoSuchProviderException,
                   IllegalBlockSizeException, BadPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        byte[] iv = ivUtils.getSecureRandomIV(GCM_IV_LENGTH);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        final byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return encodeToString(ivUtils.getPayload(iv, encrypted));

    }

    public String decrypt(String cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        final byte[] encryptedPayload = getDecoder().decode(cipherText);
        final byte[] iv = ivUtils.getIVFromEncryptedPayload(GCM_IV_LENGTH, encryptedPayload);
        final byte[] encrypted = ivUtils.getEncryptedFromEncryptedPayload(encryptedPayload, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }
}


