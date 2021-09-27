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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static com.impl.crypto.encryptors.Crypto.Transition;
import static com.impl.crypto.encryptors.Crypto.Transition.AES_GCM;
import static java.util.Base64.getDecoder;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class AESGCM {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    private Crypto crypto;
    private KeystoreFactory keystoreFactory;
    private IvUtils ivUtils;

    public AESGCM(Crypto crypto, KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.crypto = crypto;
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String plaintext, String password)
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException,
                   IllegalBlockSizeException, BadPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);
        byte[] iv = ivUtils.getSecureRandomIV(GCM_IV_LENGTH);

        Cipher cipher = Cipher.getInstance(AES_GCM.value);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        final byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return encodeToString(ivUtils.getFinalEncrypted(encrypted, iv));

    }

    public String decrypt(String cipherText, String password)
            throws NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        final byte[] encryptedPayload = getDecoder().decode(cipherText);
        final byte[] iv = ivUtils.getIVPartFromFram(encryptedPayload, GCM_IV_LENGTH);
        final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(encryptedPayload, iv);
        byte[] decrypted = crypto.doDecryption(
                encrypted,
                keystoreFactory.getKeyPKCS12(password),
                Transition.AES_GCM.value,
                new GCMParameterSpec(16 * 8, iv));

        return new String(decrypted);
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        byte[] iv = ivUtils.getSecureRandomIV(GCM_IV_LENGTH);
        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);

        Cipher cipher = Cipher.getInstance(AES_GCM.value);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        crypto.encryptionFile(inputFile, cipher, iv);
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            try (FileOutputStream outputStream = new FileOutputStream(inputFile.getParentFile() + "/decrypt_" + inputFile.getName())) {
                final byte[] iv = ivUtils.getIVPartFromFram(inputBytes, GCM_IV_LENGTH);
                final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(inputBytes, iv);
                byte[] decrypted = crypto.doDecryption(
                        encrypted,
                        keystoreFactory.getKeyPKCS12(password),
                        Transition.AES_GCM.value,
                        new GCMParameterSpec(16 * 8, iv));
                outputStream.write(decrypted);
            }
        }
    }

}






