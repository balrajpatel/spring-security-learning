package com.balraj.springsecurity.scc8jwt.controllers;

import com.balraj.springsecurity.scc8jwt.dto.LoginRequestDto;
import com.balraj.springsecurity.scc8jwt.dto.LoginResponseDto;
import com.balraj.springsecurity.scc8jwt.dto.SignupResponseDto;
import com.balraj.springsecurity.scc8jwt.service.JwtAuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {
    private final JwtAuthService jwtAuthService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto) {
        return ResponseEntity.ok(jwtAuthService.login(loginRequestDto));
    }

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signup(@RequestBody LoginRequestDto signupRequestDto) {
        return ResponseEntity.ok(jwtAuthService.signup(signupRequestDto));
    }

    @GetMapping("/demo")
    public String demo() {
        return "Hello World";
    }

    @PostMapping("/demo1")
    public  String demo1() {
        return "hello world";
    }

}
