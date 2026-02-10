package com.balraj.springsecurity.scc3ex1.config.security.filters;


import com.balraj.springsecurity.scc3ex1.config.security.authentication.CustomAuthentication;
import com.balraj.springsecurity.scc3ex1.config.security.managers.CustomAuthenticationManager;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@AllArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager customAuthenticationManager;
    public void doFilterInternal(HttpServletRequest request,
                                 HttpServletResponse response,
                                 FilterChain filterChain) throws IOException, ServletException {
        // 1. create an authentication object which is not yet authenticated
        //2. delegate the object to the authentication manager
        //3 get back the authentication from the manager
        //4 if object is authenticated then send request to the next filter.

        String key = String.valueOf(request.getHeader("key"));
        CustomAuthentication ca = new CustomAuthentication(false,key);
        var a = customAuthenticationManager.authenticate(ca);
        if(a.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(a);
            filterChain.doFilter(request, response);
        }




    }

}

/*
    AuthenticationFilter
    Part of Spring Security’s authentication engine
    Requires:
    AuthenticationManager
    AuthenticationConverter
    these are ctors parameters

    OncePerRequestFilter
    Just a plain servlet filter
    Runs once per request
    No required constructors

        Why AuthenticationFilter feels painful
    Because it’s designed for framework authors, not casual extension.
    It enforces:
    Request → convert → authenticate → success/failure handler
    When you SHOULD use AuthenticationFilter
    Use it only when:
    You are implementing a login endpoint
    You want Spring to:
    Handle success/failure
    Integrate with AuthenticationManager
    Respect authentication events
 */
