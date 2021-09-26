package com.impl.crypto.encryptors;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

@Service
public class Crypto {

    enum Transition {
        AES_GCM ("AES/GCM/NoPadding"),
        AES_CBC ("AES/CBC/PKCS5Padding"),
        CHACHA ("ChaCha20");

        String value;
        Transition(String value) {
            this.value = value;
        }
    }

    byte[] doDecryption(
            byte[] encrypted,
            Key key,
            String transition,
            AlgorithmParameterSpec parameterSpec)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
                   InvalidKeyException, InvalidAlgorithmParameterException,
                   IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(transition);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(encrypted);
    }
}

