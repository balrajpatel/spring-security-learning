package com.balraj.springsecurity.scc6ex1.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping ("/test")
public class DemoController {
    @GetMapping("/test1")
    public String test1() {
        return "test1";
    }
    @GetMapping("/test2")
    public String test2() {
        return "test2";
    }
    @PostMapping("/test1")
    public String test3() {
        return "Post test1";
    }

}
