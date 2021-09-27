package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

@Service
public class Crypto {

    enum Transition {
        AES_GCM("AES/GCM/NoPadding"),
        AES_CBC("AES/CBC/PKCS5Padding"),
        CHACHA("ChaCha20"),
        CHACHA_POLY1305("ChaCha20-Poly1305");

        String value;

        Transition(String value) {
            this.value = value;
        }
    }

    private IvUtils ivUtils;

    public Crypto(IvUtils ivUtils) {
        this.ivUtils = ivUtils;
    }

    byte[] doDecryption(byte[] encrypted, Key key, String transition,
            AlgorithmParameterSpec parameterSpec)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException,
                   BadPaddingException {

        Cipher cipher = Cipher.getInstance(transition);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(encrypted);
    }

    void encryptionFile(File inputFile, Cipher cipher, byte[] nonce)
            throws IOException, IllegalBlockSizeException, BadPaddingException {

        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            byte[] outputBytes = cipher.doFinal(inputBytes);
            final String outputFile = inputFile.getParentFile() + "/encrypt_" + inputFile.getName();
            try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                final byte[] encrypted = this.ivUtils.getFinalEncrypted(outputBytes, nonce);
                outputStream.write(encrypted);
            }
        }
    }

    void decryptFile2(File inputFile, Cipher cipher, byte[] nonce)
            throws IOException, IllegalBlockSizeException, BadPaddingException {
        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            final String putputFile = inputFile.getParentFile() + "/decrypt_" + inputFile.getName();
            try (FileOutputStream outputStream = new FileOutputStream(putputFile)) {
                final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(inputBytes, nonce);
                byte[] decrypted = cipher.doFinal(encrypted);
                outputStream.write(decrypted);
            }
        }
    }

    void decryptFile3(File inputFile, byte[] inputBytes, Cipher cipher, byte[] nonce)
            throws IOException, IllegalBlockSizeException, BadPaddingException {
        final String outputFile = inputFile.getParentFile() + "/decrypt_" + inputFile.getName();
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            final byte[] encrypted = ivUtils.getEncryptedPartFromFrame(inputBytes, nonce);
            byte[] decrypted = cipher.doFinal(encrypted);
            outputStream.write(decrypted);
        }
    }

}


