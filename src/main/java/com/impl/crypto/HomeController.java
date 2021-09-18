package com.impl.crypto;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.util.Date;

import static java.text.DateFormat.getDateTimeInstance;
import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;
import static java.util.Locale.getDefault;

@Controller
public class HomeController {

    private final Encryptor encryptor;

    public HomeController(Encryptor encryptor) {
        this.encryptor = encryptor;
    }

    @GetMapping("/crypto")
    String getTime(Model model) {
        setDate(model);
        model.addAttribute("formData", new FormData());
        return "index";
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
        return "index";
    }

    private void setDate(Model model) {
        var date = getDateTimeInstance(
                DateFormat.LONG,
                DateFormat.LONG,
                getDefault())
                .format(new Date());
        model.addAttribute("time", date);
    }
}

