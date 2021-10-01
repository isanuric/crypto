package com.impl.crypto.asymmetric;

import com.impl.crypto.symmetric.BaseTest;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RSATest extends BaseTest {

    @Autowired
    private RSA rsa;

    @Value("${keystore.asymmetric.path}")
    private String keystoreAsymmetricPath;

    @Value("${keystore.asymmetric.password}")
    private String keystoreAsyPassword;

    @Value("${keystore.asymmetric.alias}")
    private String keystoreAsyAlias;

    @RepeatedTest(1)
    void encryptMessageKeystore() throws Exception {
        String plainText = "Initializing Spring embedded WebApplicationContext";
        final String encrypted = rsa.encrypt(plainText, keystoreAsyAlias, keystoreAsyPassword);
        assertEquals(plainText, rsa.decrypt(encrypted, keystoreAsyAlias, keystoreAsyPassword));
    }

}
