package com.springauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/api")
    public String hello() {
        return "Hello, secured API!";
    }
    
    @GetMapping("/bye")
    public String bye() {
        return "Bye, secured API!";
    }
}