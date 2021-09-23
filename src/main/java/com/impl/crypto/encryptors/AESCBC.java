package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
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

import static java.util.Base64.getDecoder;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class AESCBC {

    private static final int CBC_IV_LENGTH = 16;
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private final KeystoreFactory keystoreFactory;
    private final IvUtils ivUtils;

    public AESCBC(KeystoreFactory keystoreFactory, IvUtils ivUtils) {
        this.keystoreFactory = keystoreFactory;
        this.ivUtils = ivUtils;
    }

    public String encrypt(String message) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            final Key key = keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");
            final byte[] iv = ivUtils.getSecureRandomIV(CBC_IV_LENGTH);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            final byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return encodeToString(ivUtils.getPayload(iv, encrypted));

        } catch (IllegalBlockSizeException | BadPaddingException | IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return "";
        }
    }

    public String decrypt(String encryptedString) {
        String decryptedText = "";
        if (isEmpty(encryptedString)) {
            return decryptedText;
        }

        try {
            final byte[] encryptedPayload = getDecoder().decode(encryptedString);
            final byte[] iv = ivUtils.getIVFromEncryptedPayload(CBC_IV_LENGTH, encryptedPayload);
            final byte[] encrypted = ivUtils.getEncryptedFromEncryptedPayload(encryptedPayload, iv);

            final Key key = keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);

        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | UnrecoverableKeyException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchProviderException | NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException e) {
            e.printStackTrace();
            return decryptedText;
        }
    }

    public void doCryptoFile(int cipherMode, File inputFile, File outputFile)
            throws IOException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = this.keystoreFactory.getCipher(cipherMode);
        FileOutputStream outputStream;
        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
        }
        outputStream.close();
    }

}

