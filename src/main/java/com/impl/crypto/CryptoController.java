package com.impl.crypto;

import com.impl.crypto.asymmetric.CryptoFile;
import com.impl.crypto.symmetric.AESCBC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.util.Date;

import static java.text.DateFormat.getDateTimeInstance;
import static java.util.Locale.getDefault;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.springframework.util.StringUtils.cleanPath;

@Controller
public class CryptoController {

    @Value("${uploads.path}")
    private String uploadsPath;

    private static final String MESSAGE_ATTR = "message";
    private static final String INDEX_HTML = "index";

    private final AESCBC aesCbc;
    private final CryptoFile cryptoFile;

    public CryptoController(AESCBC aesCbc, CryptoFile cryptoFile) {
        this.aesCbc = aesCbc;
        this.cryptoFile = cryptoFile;
    }

    @GetMapping("/crypto")
    public String getTime(Model model) {
        setDate(model);
        model.addAttribute("formData", new FormData());
        return INDEX_HTML;
    }

    @PostMapping("/crypto")
    public String doCrypto(@ModelAttribute("formData") FormData formData, Model model) {
        setDate(model);
        var mode = formData.getMode();
        var text = formData.getPlainText();
        var password = formData.getPassword();
        System.out.println(password);
        var result = "";

        if (mode == Cipher.ENCRYPT_MODE) {
            try {
                result = aesCbc.encrypt(text, "");
            } catch (UnrecoverableKeyException | BadPaddingException | IllegalBlockSizeException |
                    InvalidKeyException | InvalidAlgorithmParameterException |
                    NoSuchPaddingException | NoSuchAlgorithmException | KeyStoreException |
                    IOException | CertificateException e) {
                e.printStackTrace();
            }
        } else if (mode == Cipher.DECRYPT_MODE) {
            try {
                result = aesCbc.decrypt(text, "");
            } catch (UnrecoverableKeyException | BadPaddingException | IllegalBlockSizeException |
                    InvalidKeyException | InvalidAlgorithmParameterException |
                    NoSuchPaddingException | NoSuchAlgorithmException | KeyStoreException |
                    IOException | CertificateException e) {
                e.printStackTrace();
            }
        }

        model.addAttribute("cryptoResult", result);
        return INDEX_HTML;
    }

    private void setDate(Model model) {
        var date = getDateTimeInstance(DateFormat.LONG, DateFormat.LONG, getDefault()).format(
                new Date());
        model.addAttribute("time", date);
    }

    @PostMapping("/crypto-file")
    public String uploadFile(
            @RequestParam("file") MultipartFile multipartFile,
            @ModelAttribute("formData") FormData formData, Model model) {

        model.addAttribute("formData", new FormData());
        var redirectUrl = "redirect:/crypto";

        if (multipartFile.isEmpty() || isEmpty(multipartFile.getOriginalFilename())) {
            model.addAttribute(MESSAGE_ATTR, "Please select a file to upload.");
            return INDEX_HTML;
        }

        var fileName = cleanPath(multipartFile.getOriginalFilename());
        try {
            Path path = Paths.get(uploadsPath + fileName);
            Files.copy(multipartFile.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
            aesCbc.encryptFile(new File(uploadsPath + fileName), "2LS4U!%GcSr$qpV$43k%");

        } catch (IOException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException | KeyStoreException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
            model.addAttribute(MESSAGE_ATTR,
                    "Can not execute cryptography process: " + e.getMessage());
            return INDEX_HTML;
        }

        model.addAttribute(MESSAGE_ATTR, "Cryptography process successfully done for: " + fileName);
        return redirectUrl;
    }
}
