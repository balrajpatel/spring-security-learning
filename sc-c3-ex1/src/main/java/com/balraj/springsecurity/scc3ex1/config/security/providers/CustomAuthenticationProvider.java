package com.balraj.springsecurity.scc3ex1.config.security.providers;

import com.balraj.springsecurity.scc3ex1.config.security.authentication.CustomAuthentication;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Value("${our.very.very.sercret.key}")
    private String key;
    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
        String headerKey = customAuthentication.getKey();
        if(key.equals(headerKey)) {
            return new CustomAuthentication(true,null);
        }
        // return null //if not authenticated returning null will store in security context;
        throw new BadCredentialsException("Bad credentials");
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }
}
