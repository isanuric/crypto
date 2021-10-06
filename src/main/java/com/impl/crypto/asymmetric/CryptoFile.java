package com.impl.crypto.asymmetric;

import com.impl.crypto.CryptoException;
import com.impl.crypto.IvUtils;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class CryptoFile {

    private static final int AES_KEYSIZE = 256;
    private static final int IV_LENGTH = 16;
    private static final int GCM_TAG_LENGTH = 16;
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";

    private IvUtils ivUtils;
    private KeyFactoryAsymmetric keyFactory;

    public CryptoFile(IvUtils ivUtils, KeyFactoryAsymmetric keyFactory) {
        this.ivUtils = ivUtils;
        this.keyFactory = keyFactory;
    }

    void encryptFileAndDeleteOriginal(File inputFile, String password)
            throws InvalidAlgorithmParameterException, UnrecoverableKeyException,
                   NoSuchPaddingException, IllegalBlockSizeException, CertificateException,
                   IOException, KeyStoreException, NoSuchAlgorithmException, BadPaddingException,
                   InvalidKeyException, CryptoException {

        encryptFile(inputFile, password);

        decryptFile(new File(inputFile + ".enc"), password);
        final File decryptedFile = new File(inputFile + ".enc.dec");

        if (FileUtils.contentEquals(inputFile, decryptedFile)) {
            inputFile.delete();
            decryptedFile.delete();
        } else {
            throw new CryptoException("File is corrupt");
        }
    }

    void encryptFile(File inputFile, String password)
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
            fileOutputStream.write(iv);

            // write cipher text to file
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, secretKey, iv);
            byte[] inputBytes = new byte[(int) inputFile.length()];

            try (FileInputStream fileInputStream = new FileInputStream(inputFile)) {
                fileInputStream.read(inputBytes);
                fileOutputStream.write(cipher.doFinal(inputBytes));
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

        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    void decryptFile(File inputFile, String password)
            throws IOException, UnrecoverableKeyException, NoSuchPaddingException,
                   IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException,
                   KeyStoreException, BadPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException {

        try (FileInputStream fileInputStream = new FileInputStream(inputFile)) {
            SecretKeySpec secretKeySpec = decryptSecretKey(password, fileInputStream);

            byte[] iv = new byte[IV_LENGTH];
            fileInputStream.read(iv);

            Cipher cipher = getCipher(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            byte[] inputBytes = new byte[(int) inputFile.length() - AES_KEYSIZE - IV_LENGTH];
            fileInputStream.read(inputBytes);

            try (FileOutputStream outputStream = new FileOutputStream(inputFile + ".dec")) {
                outputStream.write(cipher.doFinal(inputBytes));
            }
        }
    }

    private SecretKeySpec decryptSecretKey(String password, FileInputStream fileInputStream)
            throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, IOException,
                   CertificateException, UnrecoverableKeyException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1);
        final Key privateKey = this.keyFactory.getKeyPair(password).getPrivate();
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] secretKey = new byte[AES_KEYSIZE];
        fileInputStream.read(secretKey);
        return new SecretKeySpec(cipher.doFinal(secretKey), "AES");
    }

    private Cipher getCipher(int cipherMode, SecretKey secretKey, byte[] iv)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(cipherMode, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
        return cipher;
    }

}

