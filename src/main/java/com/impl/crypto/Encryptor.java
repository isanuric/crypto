package com.impl.crypto;

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
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static java.lang.System.arraycopy;
import static java.util.Base64.getDecoder;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class Encryptor {

    private KeystoreFactory keystoreFactory;

    public Encryptor(KeystoreFactory cipher) {
        this.keystoreFactory = cipher;
    }

    public String encrypt(String message) {
        try {
            byte[] iv = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            final Key key = keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            final byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // payload = iv + encrypted
            final byte[] payload = new byte[iv.length + encrypted.length];
            arraycopy(iv, 0, payload, 0, iv.length);
            arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
            return encodeToString(payload);

        } catch (IllegalBlockSizeException | BadPaddingException | IOException | KeyStoreException |
                CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException |
                NoSuchProviderException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException e) {
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
            final byte[] iv = getIV(encryptedPayload);
            final byte[] encrypted = getEncrypted(encryptedPayload, iv);

            final Key key = keystoreFactory.getKey("K2sTgHZ6$rTNmasdDSAfjtu6754$EDFRt5");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);

        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException |
                UnrecoverableKeyException | InvalidKeyException | InvalidAlgorithmParameterException
                | NoSuchProviderException | NoSuchAlgorithmException | KeyStoreException |
                IOException | CertificateException e) {
            e.printStackTrace();
            return decryptedText;
        }
    }

    private byte[] getIV(byte[] encryptedPayload) {
        byte[] iv = new byte[16];
        arraycopy(encryptedPayload, 0, iv, 0, iv.length);
        return iv;
    }

    private byte[] getEncrypted(byte[] encryptedPayload, byte[] iv) {
        byte[] encrypted = new byte[encryptedPayload.length - iv.length];
        arraycopy(encryptedPayload, iv.length, encrypted, 0, encrypted.length);
        return encrypted;
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




