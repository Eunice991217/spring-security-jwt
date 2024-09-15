package com.example.securityprac.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    @PostMapping("/admin")
    public String adminP() {
        return "admin controller";
    }

}
