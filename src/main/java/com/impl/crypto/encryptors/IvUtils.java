package com.impl.crypto.encryptors;

import org.springframework.stereotype.Component;

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static java.lang.System.arraycopy;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

@Component
public class IvUtils {

    public static final String PERSONALIZATION_STRING = "dfkTERW54fdkGHGH78)fgfFLufg$/HÜQAvcdgzZT";

    byte[] generateSecureRandomIV(final int ivLength) {
        byte[] iv = new byte[ivLength];
        SecureRandom secureRandom = getSecureRandom();
        secureRandom.nextBytes(iv);
        return iv;
    }

    SecureRandom getSecureRandom() {
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstance(
                    "DRBG",
                    DrbgParameters.instantiation(
                            256,
                            // Periodically reseed to avoid too many outputs from a single seed.
                            PR_AND_RESEED,
                            PERSONALIZATION_STRING.getBytes())
            );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return secureRandom;
    }

    /**
     * payload = (iv + encrypted)
     */
    byte[] getFinalEncrypted(byte[] encrypted, byte[] iv) {
        final byte[] payload = new byte[iv.length + encrypted.length];
        arraycopy(iv, 0, payload, 0, iv.length);
        arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
        return payload;
    }

    byte[] getIVPartFromFram(byte[] encryptedPayload, final int ivLength) {
        byte[] iv = new byte[ivLength];
        arraycopy(encryptedPayload, 0, iv, 0, iv.length);
        return iv;
    }

    byte[] getEncryptedPartFromFrame(byte[] encryptedPayload, byte[] iv) {
        byte[] encrypted = new byte[encryptedPayload.length - iv.length];
        arraycopy(encryptedPayload, iv.length, encrypted, 0, encrypted.length);
        return encrypted;
    }

}
