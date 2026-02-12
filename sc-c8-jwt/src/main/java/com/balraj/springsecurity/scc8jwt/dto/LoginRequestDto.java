package com.balraj.springsecurity.scc8jwt.dto;


import lombok.Data;

@Data
public class LoginRequestDto {
    private String username;
    private String password;
}
