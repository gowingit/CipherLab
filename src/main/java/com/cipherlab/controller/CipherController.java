package com.cipherlab.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST Controller for CipherLab API
 */
@RestController
@RequestMapping("/api")
public class CipherController {

    @GetMapping("/health")
    public String health() {
        return "CipherLab is running!";
    }
}

