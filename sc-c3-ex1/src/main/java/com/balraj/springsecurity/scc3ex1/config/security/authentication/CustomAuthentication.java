package com.balraj.springsecurity.scc3ex1.config.security.authentication;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;

// it doesn't require to be in spring context, since we store it in SpringContextHolder
@Data
@AllArgsConstructor
public class CustomAuthentication implements Authentication {

    private final boolean authentication;
    private final String key;
    @Override
    public boolean isAuthenticated() {
        return authentication;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public @Nullable Object getCredentials() {
        return null;
    }

    @Override
    public @Nullable Object getDetails() {
        return null;
    }

    @Override
    public @Nullable Object getPrincipal() {
        return null;
    }



    @Override
    public Builder<?> toBuilder() {
        return Authentication.super.toBuilder();
    }

    @Override
    public String getName() {
        return "";
    }


}
