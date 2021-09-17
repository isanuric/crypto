package com.impl.crypto;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import static java.text.DateFormat.getDateTimeInstance;
import static java.util.Arrays.*;
import static java.util.Locale.getDefault;

@Controller
public class HomeController {

    private Encryptor encryptor;

    public HomeController(Encryptor encryptor) {
        this.encryptor = encryptor;
    }

    @GetMapping("/time")
    String getTime(Model model) {
        // var date = getDateTimeInstance(DateFormat.LONG, DateFormat.LONG, getDefault()).format(new Date());
        // model.addAttribute("time", date);
        //
        // model.addAttribute("cars", new ArrayList<>(asList("Encrypt", "Decrypt")));
        //
        // try {
        //     var encrypted = encryptor.doCrypto(Cipher.ENCRYPT_MODE, "abcd".getBytes());
        //     model.addAttribute("encrypted", new String(encrypted));
        //     var decrypted = encryptor.doCrypto(Cipher.DECRYPT_MODE, encrypted);
        //     model.addAttribute("decrypted", new String(decrypted));
        //
        // } catch (CryptoException | IllegalBlockSizeException | BadPaddingException e) {
        //     e.printStackTrace();
        // }

        model.addAttribute("formData", new FormData());
        return "index";
    }

    @PostMapping("/time")
    public String encrypt(@ModelAttribute("formData") FormData formData, Model model) {

        model.addAttribute("cars", new ArrayList<>(asList("Encrypt", "Decrypt")));
        System.out.println(formData.getMode());

        try {
            var encrypted = encryptor.doCrypto(formData.getMode(), formData.getPlainText().getBytes());
            model.addAttribute("encrypted", new String(encrypted));
        } catch (CryptoException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return "index";
    }
}
