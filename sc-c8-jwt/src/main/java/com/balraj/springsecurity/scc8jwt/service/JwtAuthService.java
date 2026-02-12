package com.balraj.springsecurity.scc8jwt.service;


import com.balraj.springsecurity.scc8jwt.dto.LoginRequestDto;
import com.balraj.springsecurity.scc8jwt.dto.LoginResponseDto;
import com.balraj.springsecurity.scc8jwt.dto.SignupResponseDto;
import com.balraj.springsecurity.scc8jwt.entity.User;
import com.balraj.springsecurity.scc8jwt.repositores.JpaUserRepository;
import com.balraj.springsecurity.scc8jwt.security.AuthUtil;
import com.balraj.springsecurity.scc8jwt.security.SecurityUser;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Service
@AllArgsConstructor
public class JwtAuthService {


    private final AuthenticationManager authenticationManager;
    private final AuthUtil authUtil;
    private final JpaUserRepository jpaUserRepository;
    private final PasswordEncoder passwordEncoder;

    public LoginResponseDto login(LoginRequestDto loginRequestDto) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword())
            );
            // User user = (User) authentication.getPrincipal();  since authentication stores the
            // default UserDetails obj or the custom UserDetails which implements it, not the entity,
            SecurityUser securityUser =
                    (SecurityUser) authentication.getPrincipal();

            User user = securityUser.getUser();

            String token = authUtil.generateAccessToken(user);
            return new LoginResponseDto(token, user.getId());
        }catch (Exception e) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid username or password"
            );
        }

    }

    public SignupResponseDto signup(LoginRequestDto signupRequestDto) {

        Optional<User> existingUser =
                jpaUserRepository.findByUsername(signupRequestDto.getUsername());

        if (existingUser.isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        User user = jpaUserRepository.save(
                User.builder()
                        .username(signupRequestDto.getUsername())
                        .password(passwordEncoder.encode(signupRequestDto.getPassword()))
                        .build()
        );

        return new SignupResponseDto(user.getId(), user.getUsername());
    }

    }

