package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
    public static final String AES_GCM = "AES/GCM/NoPadding";

    private KeystoreFactory keystoreFactory;
    private IvUtils ivUtils;

    public AESGCM(KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String plaintext, String password)
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException, NoSuchProviderException,
                   IllegalBlockSizeException, BadPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        byte[] iv = ivUtils.getSecureRandomIV(GCM_IV_LENGTH);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKey(password);

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        final byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return encodeToString(ivUtils.getPayload(iv, encrypted));

    }

    public String decrypt(String cipherText, String password)
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        final byte[] encryptedPayload = getDecoder().decode(cipherText);
        final byte[] decrypted = decryptBytes(encryptedPayload, password);
        return new String(decrypted);
    }

    public void encryptFile(File inputFile)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(AES_GCM);
        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");

        byte[] iv = ivUtils.getSecureRandomIV(GCM_IV_LENGTH);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);
            final byte[] payload = ivUtils.getPayload(iv, outputBytes);

            final File parentFile = inputFile.getParentFile();
            final String fileName = inputFile.getName();
            try (FileOutputStream outputStream = new FileOutputStream(parentFile + "/encrypted_" + fileName)) {
                outputStream.write(payload);
            }
        }
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] decrypted = decryptBytes(inputBytes, password);
            try (FileOutputStream outputStream = new FileOutputStream(
                            inputFile.getParentFile() + "/decrypt_" + inputFile.getName())) {
                outputStream.write(decrypted);
            }
        }
    }

    private byte[] decryptBytes(byte[] inputBytes, String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, KeyStoreException,
                   CertificateException, UnrecoverableKeyException, NoSuchProviderException,
                   InvalidKeyException, InvalidAlgorithmParameterException,
                   IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(AES_GCM);
        final byte[] iv = ivUtils.getIVPartFromPayload(GCM_IV_LENGTH, inputBytes);

        cipher.init(
                Cipher.DECRYPT_MODE,
                keystoreFactory.getKey(password),
                new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));

        final byte[] encrypted = ivUtils.getEncryptedPartFromPayload(inputBytes, iv);
        return cipher.doFinal(encrypted);
    }

}



