package com.impl.crypto.symmetric;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static java.lang.System.arraycopy;
import static java.security.DrbgParameters.Capability.PR_AND_RESEED;

@Component
public class IvUtils {

    @Value("${secureRandom.personalization}")
    private String personalizationString;

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
                            personalizationString.getBytes())
            );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return secureRandom;
    }

    /**
     * payload = (iv + encrypted)
     */
    byte[] addIvToEncrypted(byte[] encrypted, byte[] iv) {
        final byte[] payload = new byte[iv.length + encrypted.length];
        arraycopy(iv, 0, payload, 0, iv.length);
        arraycopy(encrypted, 0, payload, iv.length, encrypted.length);
        return payload;
    }

    byte[] getIVPartFromFrame(File inputFile, final int ivLength) throws IOException {
        try (FileInputStream inputStream = new FileInputStream(inputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            return this.getIVPartFromFrame(inputBytes, ivLength);
        }
    }

    byte[] getIVPartFromFrame(byte[] encryptedPayload, final int ivLength) {
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
