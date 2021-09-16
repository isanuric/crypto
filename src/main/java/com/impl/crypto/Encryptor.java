package com.impl.crypto;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

@Service
public class Encryptor {

    private CipherFactory cipherFactory;

    public Encryptor(CipherFactory cipher) {
        this.cipherFactory = cipher;
    }

    public byte[] encryptMessage(byte[] message, byte[] keyBytes)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
                   BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(message);
    }

    public byte[] decryptMessage(byte[] encryptedMessage, byte[] keyBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
                   BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedMessage);
    }

    public byte[] encryptMessageKeystore(final String message)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
                   BadPaddingException, IllegalBlockSizeException, CertificateException,
                   IOException, KeyStoreException, UnrecoverableKeyException,
                   InvalidAlgorithmParameterException {

        Cipher cipher = this.cipherFactory.getCipher(Cipher.ENCRYPT_MODE);
        return cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decryptMessageKeystore(byte[] message)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
                   BadPaddingException, IllegalBlockSizeException, CertificateException,
                   IOException, KeyStoreException, UnrecoverableKeyException,
                   InvalidAlgorithmParameterException {

        Cipher cipher = this.cipherFactory.getCipher(Cipher.DECRYPT_MODE);
        return cipher.doFinal(message);
    }

}

