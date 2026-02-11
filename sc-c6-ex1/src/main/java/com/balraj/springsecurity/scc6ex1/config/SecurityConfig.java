package com.balraj.springsecurity.scc6ex1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.PathMatcher;

@Configuration
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        var uds = new InMemoryUserDetailsManager();
        var user1 = User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .authorities("read") // equivalent with  ROLE_ADMIN authority;
                .build();
        var user2 = User.withUsername("user2")
                .password(passwordEncoder().encode("password2"))
                .authorities("write")
                .build();
        uds.createUser(user1);
        uds.createUser(user2);
        return uds;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, PathMatcher mvcPathMatcher) throws Exception {
        return http .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET,"/test/**").hasAuthority("write")
                        .anyRequest().authenticated()
                )

                        .build();
    }


}
