package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static com.impl.crypto.encryptors.Crypto.Transition;
import static java.util.Base64.getDecoder;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class AESCBC {

    private static final int CBC_IV_LENGTH = 16;
    private static final String AES_CBC = "AES/CBC/PKCS5Padding";

    private Crypto crypto;
    private final KeystoreFactory keystoreFactory;
    private final IvUtils ivUtils;

    public AESCBC(Crypto crypto, KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.crypto = crypto;
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String message, String password) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC);
            final Key key = keystoreFactory.getKey(password);
            final byte[] iv = ivUtils.getSecureRandomIV(CBC_IV_LENGTH);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            final byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return encodeToString(ivUtils.getPayload(iv, encrypted));

        } catch (IllegalBlockSizeException | BadPaddingException | IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return "";
        }
    }

    public String decrypt(String encryptedString, String password) {
        String decryptedText = "";
        if (isEmpty(encryptedString)) {
            return decryptedText;
        }

        try {
            final byte[] encryptedPayload = getDecoder().decode(encryptedString);
            final byte[] iv = ivUtils.getIVPartFromPayload(CBC_IV_LENGTH, encryptedPayload);
            final byte[] encrypted = ivUtils.getEncryptedPartFromPayload(encryptedPayload, iv);

            final Key key = keystoreFactory.getKey(password);
            Cipher cipher = Cipher.getInstance(AES_CBC);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);

        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | UnrecoverableKeyException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException e) {
            e.printStackTrace();
            return decryptedText;
        }
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException, NoSuchProviderException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher cipher = Cipher.getInstance(AES_CBC);
        final byte[] key = keystoreFactory.getKey(password).getEncoded();
        SecretKeySpec secretKeySpecification = new SecretKeySpec(key, "AES");
        final byte[] iv = ivUtils.getSecureRandomIV(16);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpecification, new IvParameterSpec(iv));

        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);

            try (FileOutputStream outputStream = new FileOutputStream(
                    inputFile.getParentFile() + "/encrypted_cbc_" + inputFile.getName())) {
                final byte[] payload = ivUtils.getPayload(iv, outputBytes);
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

            try (FileOutputStream outputStream = new FileOutputStream(inputFile.getParentFile() + "/decrypt_" + inputFile.getName())) {
                final byte[] iv = ivUtils.getIVPartFromPayload(16, inputBytes);
                final byte[] encrypted = ivUtils.getEncryptedPartFromPayload(inputBytes, iv);
                byte[] decrypted = this.crypto.doDecryption(encrypted, iv, password, Transition.AES_CBC);
                outputStream.write(decrypted);
            }
        }
    }

}



