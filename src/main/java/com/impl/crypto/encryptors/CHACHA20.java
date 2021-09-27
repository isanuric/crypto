package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
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

import static com.impl.crypto.encryptors.Crypto.Transition.CHACHA;
import static java.util.Base64.getDecoder;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class CHACHA20 {

    private static final int COUNTER = 10;
    private static final int CHACHA_IV_LENGTH = 12;
    private static final String TRANSFORMATION_CHACHA = "ChaCha20";

    private Crypto crypto;
    private KeystoreFactory keystoreFactory;
    private IvUtils ivUtils;

    public CHACHA20(Crypto crypto, KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.crypto = crypto;
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String plainText, String password)
            throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        SecretKey key = keystoreFactory.getKeyBKS(password);
        byte[] nonce = ivUtils.getSecureRandomIV(CHACHA_IV_LENGTH);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION_CHACHA);
        ChaCha20ParameterSpec cha20ParameterSpec = new ChaCha20ParameterSpec(nonce, COUNTER);
        cipher.init(Cipher.ENCRYPT_MODE, key, cha20ParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return encodeToString(ivUtils.getFinalEncrypted(encrypted, nonce));
    }
    public String decrypt(String cipherText, String password)
            throws UnrecoverableKeyException, NoSuchPaddingException, CertificateException,
                   IOException, KeyStoreException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException,
                   BadPaddingException, InvalidKeyException {

        final byte[] cipherTextDecoded = getDecoder().decode(cipherText);
        final byte[] nonce = ivUtils.getIVPartFromFram(cipherTextDecoded, CHACHA_IV_LENGTH);
        final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(cipherTextDecoded, nonce);

        return new String(crypto.doDecryption(
                        encrypted,
                        keystoreFactory.getKeyBKS(password),
                        Crypto.Transition.CHACHA.value,
                        new ChaCha20ParameterSpec(nonce, COUNTER))
        );
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);
        byte[] nonce = ivUtils.getSecureRandomIV(CHACHA_IV_LENGTH);

        Cipher cipher = initCipherChaCha(Cipher.ENCRYPT_MODE, key, nonce);
        crypto.encryptionFile(inputFile, cipher, nonce);
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        final SecretKeySpec key = (SecretKeySpec) keystoreFactory.getKeyPKCS12(password);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        FileInputStream inputStream = new FileInputStream(inputFile);
        inputStream.read(inputBytes);
        final byte[] nonce = ivUtils.getIVPartFromFram(inputBytes, CHACHA_IV_LENGTH);

        Cipher cipher = initCipherChaCha(Cipher.DECRYPT_MODE, key, nonce);
        crypto.decryptFile3(inputFile, inputBytes, cipher, nonce);
    }

    private Cipher initCipherChaCha(int cipherMode, SecretKey key, byte[] nonce)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(CHACHA.value);
        ChaCha20ParameterSpec cha20ParameterSpec = new ChaCha20ParameterSpec(nonce, COUNTER);
        cipher.init(cipherMode, key, cha20ParameterSpec);
        return cipher;
    }

}

