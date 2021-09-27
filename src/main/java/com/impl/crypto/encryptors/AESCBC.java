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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static com.impl.crypto.encryptors.Crypto.Transition.AES_CBC;
import static java.util.Base64.getDecoder;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class AESCBC {

    private static final int CBC_IV_LENGTH = 16;

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
            Cipher cipher = Cipher.getInstance(AES_CBC.value);
            final Key key = keystoreFactory.getKeyPKCS12(password);
            final byte[] iv = ivUtils.getSecureRandomIV(CBC_IV_LENGTH);
            cipher.init(Cipher.ENCRYPT_MODE, key, getIvParameterSpec(iv));
            final byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return encodeToString(ivUtils.getFinalEncrypted(encrypted, iv));

        } catch (IllegalBlockSizeException | BadPaddingException | IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
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
            final byte[] iv = ivUtils.getIVPartFromFram(encryptedPayload, CBC_IV_LENGTH);
            final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(encryptedPayload, iv);

            final Key key = keystoreFactory.getKeyPKCS12(password);
            Cipher cipher = Cipher.getInstance(AES_CBC.value);
            cipher.init(Cipher.DECRYPT_MODE, key, getIvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);

        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | UnrecoverableKeyException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException e) {
            e.printStackTrace();
            return decryptedText;
        }
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);
        final byte[] iv = ivUtils.getSecureRandomIV(16);

        Cipher cipher = Cipher.getInstance(AES_CBC.value);
        cipher.init(Cipher.ENCRYPT_MODE, key,  getIvParameterSpec(iv));

        crypto.encryptionFile(inputFile, cipher, iv);
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        byte[] inputBytes = new byte[(int) inputFile.length()];
        final byte[] iv = ivUtils.getIVPartFromFram(inputBytes, 16);
        final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(inputBytes, iv);

        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            inputStream.read(inputBytes);

            try (FileOutputStream outputStream = new FileOutputStream(inputFile.getParentFile() + "/decrypt_" + inputFile.getName())) {

                byte[] decrypted = this.crypto.doDecryption(
                        encrypted,
                        keystoreFactory.getKeyPKCS12(password),
                        AES_CBC.value,
                        getIvParameterSpec(iv));

                outputStream.write(decrypted);
            }
        }
    }

    private IvParameterSpec getIvParameterSpec(byte[] iv) {
        return new IvParameterSpec(iv);
    }

}
