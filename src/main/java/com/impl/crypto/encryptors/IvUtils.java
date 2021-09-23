package com.impl.crypto.encryptors;

import org.springframework.stereotype.Component;

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static java.lang.System.arraycopy;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

@Component
public class IvUtils {

     byte[] getSecureRandomIV(final int ivLength) {
        byte[] iv = new byte[ivLength];
        SecureRandom drbgSecureRandom;
        try {
            drbgSecureRandom = SecureRandom.getInstance(
                    "DRBG",
                    DrbgParameters.instantiation(
                            256,
                            PR_AND_RESEED,
                            "dfkTERW54fdkGHGH78)fgfFLufg$/HÜQAvcdgzZTEJKLQD5847fdsf%tD".getBytes())
            );
            drbgSecureRandom.nextBytes(iv);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return iv;
    }

    /**
     * payload = (iv + encrypted)
     */
     byte[] getPayload(byte[] iv, byte[] encrypted) {
        final byte[] payload = new byte[iv.length + encrypted.length];
        arraycopy(iv, 0, payload, 0, iv.length);
        arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
        return payload;
    }

     byte[] getIVFromEncryptedPayload(final int ivLength, byte[] encryptedPayload) {
        byte[] iv = new byte[ivLength];
        arraycopy(encryptedPayload, 0, iv, 0, iv.length);
        return iv;
    }

     byte[] getEncryptedFromEncryptedPayload(byte[] encryptedPayload, byte[] iv) {
        byte[] encrypted = new byte[encryptedPayload.length - iv.length];
        arraycopy(encryptedPayload, iv.length, encrypted, 0, encrypted.length);
        return encrypted;
    }

}
