package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.FileInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESGCMTest extends BaseTest {

    @Autowired
    private AESGCM aesGcm;

    @RepeatedTest(1)
    void encryptMessageKeystore() throws Exception {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        final String encrypted = aesGcm.encrypt(
                plainText,
                "fVD5y2*ZNK3K8nD#jgvoLbjVpW9bQpS4U!%GcSr$qpV$4z3k%Vcc$U$N!YF#j#MoGbP%M");
        assertEquals(
                plainText,
                aesGcm.decrypt(
                        encrypted,
                "fVD5y2*ZNK3K8nD#jgvoLbjVpW9bQpS4U!%GcSr$qpV$4z3k%Vcc$U$N!YF#j#MoGbP%M"));
    }

    @Test
    void doCryptoFile() throws Exception {
        aesGcm.encryptFile(new File("src/main/resources/files/inputFile.txt"));
        aesGcm.decryptFile(
                new File("src/main/resources/files/encrypted_inputFile.txt"),
                "fVD5y2*ZNK3K8nD#jgvoLbjVpW9bQpS4U!%GcSr$qpV$4z3k%Vcc$U$N!YF#j#MoGbP%M");

        assertEquals(
                new FileInputStream("src/main/resources/files/inputFile.txt").read(),
                new FileInputStream("src/main/resources/files/decrypted_encrypted_inputFile.txt").read());
    }

}
