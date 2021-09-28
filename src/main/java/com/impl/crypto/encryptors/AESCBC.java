package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;

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

    public String encrypt(String message, String password)
            throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        final byte[] iv = ivUtils.generateSecureRandomIV(CBC_IV_LENGTH);

        Cipher cipher = initCipherAESCBC(Cipher.ENCRYPT_MODE, iv, password);
        final byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return encodeToString(ivUtils.getFinalEncrypted(encrypted, iv));
    }

    public String decrypt(String cipherText, String password)
            throws InvalidAlgorithmParameterException, UnrecoverableKeyException,
                   NoSuchPaddingException, CertificateException, NoSuchAlgorithmException,
                   IOException, KeyStoreException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException {

        if (isEmpty(cipherText)) {
            return "";
        }

        final byte[] frame = getDecoder().decode(cipherText);
        final byte[] iv = ivUtils.getIVPartFromFram(frame, CBC_IV_LENGTH);
        final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(frame, iv);

        Cipher cipher = initCipherAESCBC(Cipher.DECRYPT_MODE, iv, password);
        return new String(cipher.doFinal(encrypted));
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException, InvalidAlgorithmParameterException,
                   InvalidKeyException {

        final byte[] iv = ivUtils.generateSecureRandomIV(16);

        Cipher cipher = initCipherAESCBC(Cipher.ENCRYPT_MODE, iv, password);
        crypto.encryptFile(inputFile, cipher, iv);
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException,
                   CertificateException, KeyStoreException, InvalidAlgorithmParameterException,
                   InvalidKeyException {

        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            final byte[] iv = ivUtils.getIVPartFromFram(inputBytes, 16);

            Cipher cipher = initCipherAESCBC(Cipher.DECRYPT_MODE, iv, password);
            crypto.decryptFile3(inputFile, inputBytes, cipher, iv);
        }
    }

    private Cipher initCipherAESCBC(int cipherMode, byte[] iv, String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException {

        final SecretKey key = (SecretKey) keystoreFactory.getKeyPKCS12(password);

        Cipher cipher = Cipher.getInstance(AES_CBC.value);
        AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(cipherMode, key, ivParameterSpec, ivUtils.getSecureRandom());
        return cipher;
    }

}
