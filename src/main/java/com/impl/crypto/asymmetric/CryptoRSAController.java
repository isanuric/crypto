package com.impl.crypto.asymmetric;

import com.impl.crypto.CryptoException;
import com.impl.crypto.FormData;
import com.impl.crypto.symmetric.AESCBC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
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

@RestController
@CrossOrigin
@RequestMapping("/asy")
public class CryptoRSAController {

    @Value("${uploads.path}")
    private String uploadsPath;

    private static final String MESSAGE_ATTR = "message";
    private static final String INDEX_HTML = "index";

    private final AESCBC aesCbc;
    private final CryptoFile cryptoFile;

    public CryptoRSAController(AESCBC aesCbc, CryptoFile cryptoFile) {
        this.aesCbc = aesCbc;
        this.cryptoFile = cryptoFile;
    }

    @GetMapping("/crypto")
    public String getTime(Model model) {
        setDate(model);
        model.addAttribute("formData", new FormData());
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
            cryptoFile.encryptFileAndDeleteOriginal(new File(uploadsPath + fileName), formData.getPassword());

        } catch (IOException | IllegalBlockSizeException | BadPaddingException |
                NoSuchPaddingException | NoSuchAlgorithmException | UnrecoverableKeyException |
                CertificateException | KeyStoreException | InvalidAlgorithmParameterException |
                InvalidKeyException | CryptoException e) {
            e.printStackTrace();
            model.addAttribute(MESSAGE_ATTR,"Can not execute cryptography process: " + e.getMessage());
            return INDEX_HTML;
        }

        model.addAttribute(MESSAGE_ATTR, "Cryptography process successfully done for: " + fileName);
        return redirectUrl;
    }

    @PostMapping("/c-t")
    public String getReact(@RequestBody FormData formData) {
        System.out.println(formData.getPlainText());
        System.out.println(formData.getPassword());
        return "done";
    }

}




