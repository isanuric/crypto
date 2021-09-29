package com.impl.crypto.symmetric;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;

import static com.impl.crypto.symmetric.Crypto.Transition.CHACHA_POLY1305;
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

        byte[] nonce = ivUtils.generateSecureRandomIV(CHACHA_IV_LENGTH);

        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, nonce, password);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return encodeToString(ivUtils.addIvToEncrypted(encrypted, nonce));
    }

    public String decrypt(String cipherText, String password)
            throws UnrecoverableKeyException, NoSuchPaddingException, CertificateException,
                   IOException, KeyStoreException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException,
                   BadPaddingException, InvalidKeyException {

        final byte[] cipherTextDecoded = Base64.getDecoder().decode(cipherText);
        final byte[] nonce = ivUtils.getIVPartFromFrame(cipherTextDecoded, CHACHA_IV_LENGTH);
        final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(cipherTextDecoded, nonce);

        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, nonce, password);
        return new String(cipher.doFinal(encrypted));
    }

    public void encryptFile(File inputFile, String password)
            throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {

        byte[] nonce = ivUtils.generateSecureRandomIV(CHACHA_IV_LENGTH);

        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, nonce, password);
        crypto.encryptFile(inputFile, cipher, nonce);
    }

    public void decryptFile(File inputFile, String password)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   UnrecoverableKeyException, CertificateException, KeyStoreException,
                   NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidAlgorithmParameterException, InvalidKeyException {

        final byte[] nonce = ivUtils.getIVPartFromFrame(inputFile, CHACHA_IV_LENGTH);

        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, nonce, password);
        crypto.decryptFile(inputFile, cipher, nonce);
    }

    private Cipher getCipher(int cipherMode, byte[] nonce, String password)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException, UnrecoverableKeyException,
                   CertificateException, IOException, KeyStoreException {

        Cipher cipher = Cipher.getInstance(CHACHA_POLY1305.value);
        cipher.init(
                cipherMode,
                keystoreFactory.getKeyBKS(password),
                new IvParameterSpec(nonce),
                ivUtils.getSecureRandom());
        return cipher;
    }

}
