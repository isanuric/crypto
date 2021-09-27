package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import static com.impl.crypto.encryptors.Crypto.Transition.CHACHA_POLY1305;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class CHACHA20POLY1305 {

    private static final int CHACHA_IV_LENGTH = 12;

    private Crypto crypto;
    private KeystoreFactory keystoreFactory;
    private IvUtils ivUtils;

    public CHACHA20POLY1305(Crypto crypto, KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.crypto = crypto;
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String plainText, String password)
            throws UnrecoverableKeyException, CertificateException, IOException,
                   KeyStoreException, NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        SecretKey key = keystoreFactory.getKeyBKS(password);
        byte[] nonce = ivUtils.getSecureRandomIV(CHACHA_IV_LENGTH);

        Cipher cipher = initCipherChaChaPoly1305(Cipher.ENCRYPT_MODE, key, nonce);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return encodeToString(ivUtils.getFinalEncrypted(encrypted, nonce));
    }

    public String decrypt(String cipherText, String password)
            throws UnrecoverableKeyException, NoSuchPaddingException, CertificateException,
                   IOException, KeyStoreException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException,
                   BadPaddingException, InvalidKeyException {

        final byte[] cipherTextDecoded = Base64.getDecoder().decode(cipherText);
        final byte[] nonce = ivUtils.getIVPartFromFram(cipherTextDecoded, CHACHA_IV_LENGTH);
        SecretKey key = keystoreFactory.getKeyBKS(password);
        final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(cipherTextDecoded, nonce);

        Cipher cipher = initCipherChaChaPoly1305(Cipher.DECRYPT_MODE, key, nonce);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);
        byte[] nonce = ivUtils.getSecureRandomIV(CHACHA_IV_LENGTH);

        Cipher cipher = initCipherChaChaPoly1305(Cipher.ENCRYPT_MODE, key, nonce);
        crypto.encryptionFile(inputFile, cipher, nonce);
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);
        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);
        final byte[] nonce = ivUtils.getIVPartFromFram(inputBytes, CHACHA_IV_LENGTH);

        Cipher cipher = initCipherChaChaPoly1305(Cipher.DECRYPT_MODE, key, nonce);
        crypto.decryptFile3(inputFile, inputBytes, cipher, nonce);
    }

    private Cipher initCipherChaChaPoly1305(int cipherMode, SecretKey key, byte[] nonce)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(CHACHA_POLY1305.value);
        AlgorithmParameterSpec ivParameterSpec = new IvParameterSpec(nonce) ;
        cipher.init(cipherMode, key, ivParameterSpec, ivUtils.getSecureRandom());
        return cipher;
    }

}
