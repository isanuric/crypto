package com.impl.crypto.asymmetric;

import com.impl.crypto.CryptoException;
import com.impl.crypto.symmetric.BaseTest;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class CryptoFileTest extends BaseTest {

    @Value("${keystore.asymmetric.password}")
    private String  keystoreAsymmetricPassword;

    @Autowired
    private CryptoFile cryptoFile;

    @RepeatedTest(1)
    void doCryptoFile() throws IOException, InvalidAlgorithmParameterException, UnrecoverableKeyException,
                        NoSuchPaddingException, IllegalBlockSizeException, CertificateException,
                        NoSuchAlgorithmException, BadPaddingException, KeyStoreException,
                        InvalidKeyException {

        cryptoFile.encryptFile(new File("src/main/resources/files/kant.pdf"), keystoreAsymmetricPassword);
        cryptoFile.decryptFile(new File("src/main/resources/files/kant.pdf.enc"), keystoreAsymmetricPassword);

        assertEquals(
                new FileInputStream("src/main/resources/files/kant.pdf").read(),
                new FileInputStream("src/main/resources/files/kant.pdf.enc.dec").read());
    }

    @Test
    void encryptAndDeleteOriginal()
            throws IOException, InvalidAlgorithmParameterException, UnrecoverableKeyException,
                   NoSuchPaddingException, IllegalBlockSizeException, CertificateException,
                   KeyStoreException, NoSuchAlgorithmException, BadPaddingException,
                   InvalidKeyException, CryptoException {

        final File file = getTestFile();
        cryptoFile.encryptFileAndDeleteOriginal(file, keystoreAsymmetricPassword);

        assertFalse(file.canRead());
    }

    private File getTestFile() throws IOException {
        final File file = new File("src/main/resources/files/test.txt");
        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            fileOutputStream.write("test values".getBytes(StandardCharsets.UTF_8));
        }
        return file;
    }
}
