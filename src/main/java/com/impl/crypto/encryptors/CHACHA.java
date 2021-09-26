package com.impl.crypto.encryptors;

import com.impl.crypto.encryptors.Crypto.Transition;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static java.util.Base64.getDecoder;
import static org.springframework.util.Base64Utils.encodeToString;

@Service
public class CHACHA {

    private static final int COUNTER = 10;
    private static final int CHACHA_IV_LENGTH = 12;
    private static final String TRANSFORMATION = "ChaCha20";

    private Crypto crypto;
    private KeystoreFactory keystoreFactory;
    private IvUtils ivUtils;

    public CHACHA(Crypto crypto, KeystoreFactory keystoreFactory, IvUtils ivUtils) {
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

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        ChaCha20ParameterSpec cha20ParameterSpec = new ChaCha20ParameterSpec(nonce, COUNTER);
        cipher.init(Cipher.ENCRYPT_MODE, key, cha20ParameterSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return encodeToString(ivUtils.getPayload(nonce, encrypted));
    }

    public String decrypt(String cipherText, String password)
            throws UnrecoverableKeyException, NoSuchPaddingException, CertificateException,
                   IOException, KeyStoreException, NoSuchAlgorithmException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException,
                   BadPaddingException, InvalidKeyException {

        final byte[] cipherTextDecoded = getDecoder().decode(cipherText);
        final byte[] nonce = ivUtils.getIVPartFromPayload(cipherTextDecoded, CHACHA_IV_LENGTH);
        final byte[] encrypted = ivUtils.getEncryptedPartFromPayload(cipherTextDecoded, nonce);

        return new String(crypto.doDecryption(
                        encrypted,
                        keystoreFactory.getKeyBKS(password),
                        Transition.CHACHA.value,
                        new ChaCha20ParameterSpec(nonce, COUNTER))
        );
    }
}
