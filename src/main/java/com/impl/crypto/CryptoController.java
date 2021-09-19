package com.impl.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.DateFormat;
import java.util.Date;

import static java.text.DateFormat.getDateTimeInstance;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;
import static java.util.Locale.getDefault;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Controller
public class CryptoController {

    @Value("${uploads.path}")
    private String uploadsPath;

    private static final String MESSAGE_ATTR = "message";
    private static final String INDEX_HTML = "index";
    private final Encryptor encryptor;

    public CryptoController(Encryptor encryptor) {
        this.encryptor = encryptor;
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
        try {
            var mode = formData.getMode();
            var text = formData.getText();
            var result = "";
            if (mode == Cipher.ENCRYPT_MODE) {
                var cryptoOutput = encryptor.doCrypto(mode, text.getBytes(StandardCharsets.UTF_8));
                result = getEncoder().encodeToString(cryptoOutput);

            } else if (mode == Cipher.DECRYPT_MODE) {
                var cryptoOutput = encryptor.doCrypto(mode, getDecoder().decode(text));
                result = new String(cryptoOutput);
            }
            model.addAttribute("cryptoResult", result);

        } catch (CryptoException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return INDEX_HTML;
    }

    private void setDate(Model model) {
        var date = getDateTimeInstance(
                DateFormat.LONG,
                DateFormat.LONG,
                getDefault())
                .format(new Date());
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

        var fileName = StringUtils.cleanPath(multipartFile.getOriginalFilename());
        try {
            Path path = Paths.get(uploadsPath + fileName);
            Files.copy(multipartFile.getInputStream(), path, StandardCopyOption.REPLACE_EXISTING);
            String fileNameResult = formData.getMode() == 1 ? "encrypted.txt" : "decrypted.txt";
            encryptor.doCryptoFile(
                    formData.getMode(),
                    new File(uploadsPath + fileName),
                    new File(uploadsPath + fileNameResult));

        } catch (IOException | CryptoException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            model.addAttribute(MESSAGE_ATTR, "Can not execute cryptography process: " + e.getMessage());
            return INDEX_HTML;
        }

        model.addAttribute(MESSAGE_ATTR, "Cryptography process successfully done for: " + fileName);
        return redirectUrl;
    }
}


