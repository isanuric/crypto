package com.impl.crypto.encryptors;

import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESGCMTest extends BaseTest {

    @Autowired
    private AESGCM aesGcm;

    @RepeatedTest(1)
    void encryptMessageKeystore() throws Exception {
        String plainText = "Started AES_GCMTest in 1.714 seconds (JVM running for 2.745)";
        assertEquals(plainText, aesGcm.decrypt(aesGcm.encrypt(plainText)));
    }

}
