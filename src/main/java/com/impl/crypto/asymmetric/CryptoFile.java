package com.impl.crypto.asymmetric;

import com.impl.crypto.IvUtils;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class CryptoFile {

    private static final int AES_KEYSIZE = 256;
    private static final int IV_LENGTH = 16;

    private IvUtils ivUtils;
    private KeyFactoryAsymmetric keyFactory;

    public CryptoFile(IvUtils ivUtils, KeyFactoryAsymmetric keyFactory) {
        this.ivUtils = ivUtils;
        this.keyFactory = keyFactory;
    }

    void encrypt(File inputFile, String password)
            throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
                   BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        try (FileOutputStream fileOutputStream = new FileOutputStream(inputFile + ".enc")) {
            final PublicKey publicKey = this.keyFactory.getKeyPair(password).getPublic();

            // write encrypted secret key to file
            final SecretKey secretKey = generateSecretKey();
            final byte[] encryptedSecretKey = encryptSecretKey(secretKey, publicKey);
            fileOutputStream.write(encryptedSecretKey);

            // write iv to file
            final byte[] iv = ivUtils.generateSecureRandomIV(IV_LENGTH);
            final IvParameterSpec ivspec = new IvParameterSpec(iv);
            fileOutputStream.write(iv);

            // write encrypted text to file
            try (FileInputStream fileInputStream = new FileInputStream(inputFile)) {
                Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherAES.init(Cipher.ENCRYPT_MODE, secretKey, ivspec, new SecureRandom());

                byte[] inputBytes = new byte[(int) inputFile.length()];
                fileInputStream.read(inputBytes);
                final byte[] cipherByte = cipherAES.doFinal(inputBytes);
                fileOutputStream.write(cipherByte);
            }
        }
    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEYSIZE);
        return keyGenerator.generateKey();
    }

    private byte[] encryptSecretKey(SecretKey secretKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    void decryptFile(File inputFile, String password)
            throws IOException, UnrecoverableKeyException, NoSuchPaddingException,
                   IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException,
                   KeyStoreException, BadPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException {

        try (FileInputStream fileInputStream = new FileInputStream(inputFile)) {
            SecretKeySpec secretKeySpec;
            secretKeySpec = decryptSecretKey(password, fileInputStream);

            byte[] iv = new byte[IV_LENGTH];
            fileInputStream.read(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);
            try (FileOutputStream outputStream = new FileOutputStream(inputFile + ".dec")) {
                byte[] inputBytes = new byte[(int) inputFile.length() - AES_KEYSIZE - IV_LENGTH];
                fileInputStream.read(inputBytes);
                outputStream.write(cipher.doFinal(inputBytes));
            }
        }
    }

    private SecretKeySpec decryptSecretKey(String password, FileInputStream fileInputStream)
            throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, IOException,
                   CertificateException, UnrecoverableKeyException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        final Key privateKey = this.keyFactory.getKeyPair(password).getPrivate();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] secretkey = new byte[AES_KEYSIZE];
        fileInputStream.read(secretkey);
        byte[] secretKeyDecrypted = cipher.doFinal(secretkey);
        return new SecretKeySpec(secretKeyDecrypted, "AES");
    }

}
