package com.balraj.springsecurity.scc2ex1.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
    @GetMapping("/demo")
    public String demo() {
        var v = SecurityContextHolder.getContext().getAuthentication();
        v.getAuthorities().forEach(System.out::println);
        return "Hello World";
    }
}
