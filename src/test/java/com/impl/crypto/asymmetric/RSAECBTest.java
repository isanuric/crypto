package com.impl.crypto.asymmetric;

import com.impl.crypto.symmetric.BaseTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RSAECBTest extends BaseTest {

    @Autowired
    protected RSAECB rsaecboaep;

    @Test
    void doCrypto()
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                   BadPaddingException, InvalidKeyException {
        String plainText = "Der Schlaf klopft mir auf meine Auge";
        assertEquals(plainText+"", rsaecboaep.doCrypto(plainText));
    }

}
