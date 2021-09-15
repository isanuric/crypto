package com.impl.crypto;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.text.DateFormat;
import java.util.Date;

import static java.text.DateFormat.getDateTimeInstance;
import static java.util.Locale.getDefault;

@Controller
public class HomeController {

    @GetMapping("/time")
    String getTime(Model model) {
        model.addAttribute(
                "time",
                getDateTimeInstance(DateFormat.LONG, DateFormat.LONG, getDefault()).format(new Date()));

        return "index.html";
    }
}
