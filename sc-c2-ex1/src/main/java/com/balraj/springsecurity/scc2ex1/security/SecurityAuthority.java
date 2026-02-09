package com.balraj.springsecurity.scc2ex1.security;

import com.balraj.springsecurity.scc2ex1.entity.Authority;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@AllArgsConstructor
public class SecurityAuthority implements GrantedAuthority {
    private final Authority authority;


    @Override
    public String getAuthority() {
        return authority.getName();
    }
}
