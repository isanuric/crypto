package com.impl.crypto;

import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@Service
public class Encryptor {

    private KeystoreFactory keystoreFactory;

    public Encryptor(KeystoreFactory cipher) {
        this.keystoreFactory = cipher;
    }

    public byte[] doCrypto(int cipherMode, byte[] message) {
        try {
            Cipher cipher = this.keystoreFactory.getCipher(cipherMode);
            return cipher.doFinal(message);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public void doCryptoFile(int cipherMode, File inputFile, File outputFile)
            throws IOException, IllegalBlockSizeException, BadPaddingException,
                   NoSuchAlgorithmException {

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



