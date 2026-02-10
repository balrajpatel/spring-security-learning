package com.balraj.springsecurity.scc3ex1.config;

import com.balraj.springsecurity.scc3ex1.config.security.filters.CustomAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationFilter customAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .addFilterAt(customAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .build();
    }



    //.authorizeRequests().anyRequest().authenticated()   old approach
    /*
    By defining this:

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        you are saying to Spring Security:
        “Do NOT use the default security configuration.
        Use my SecurityFilterChain instead.”``



     */
}

/*
@EnableWebSecurity
That style is now deprecated and removed.


What happens in Spring Boot 3 / Security 6
Spring Boot auto-configures web security for you when:
spring-security is on the classpath
You define a SecurityFilterChain bean
 */
