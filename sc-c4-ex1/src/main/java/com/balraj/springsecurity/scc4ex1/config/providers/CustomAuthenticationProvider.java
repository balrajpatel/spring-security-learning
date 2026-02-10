package com.balraj.springsecurity.scc4ex1.config.providers;

import com.balraj.springsecurity.scc4ex1.config.authentication.CustomAuthentication;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;


public class CustomAuthenticationProvider implements AuthenticationProvider {
    private final String key;
    public CustomAuthenticationProvider(String key) {
        this.key = key;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;

        if(key.equals(customAuthentication.getKey())) {
            customAuthentication.setAuthenticated(true);
            return customAuthentication;
        }
        throw new BadCredentialsException("Invalid API key");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.isAssignableFrom(authentication);
    }

}
