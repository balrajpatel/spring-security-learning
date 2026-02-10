package com.balraj.springsecurity.scc4ex1.config.filters;

import com.balraj.springsecurity.scc4ex1.config.authentication.CustomAuthentication;
import com.balraj.springsecurity.scc4ex1.config.managers.CustomAuthenticationManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@AllArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter {
    private final CustomAuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //checking if user is already authenticated or not
       Authentication existing =
                SecurityContextHolder.getContext().getAuthentication();

        if (existing != null && existing.isAuthenticated()) {
            System.out.println("Basic Auth filter");
            filterChain.doFilter(request, response);
            return;
        }
        /*
        */
        String apiKey = request.getHeader("apiKey");



        if(apiKey == null) {   // it tells that this authentication mechanism didn't used by client
            //apifilterkey mechanism should be skipped, since user send no key means he didn't used this mechanism
            //se we skipped
            filterChain.doFilter(request, response);
            return;

        }
        /*
        1st filter is ApiKeyFilter,
        so if apikey==null, so our ApiKeyFilter did nothing,
        execution goes to 2nd filter ie, basic auth
         */

        /*
        if apikey!=null , then
        below directly happens

         */

      try {
          CustomAuthentication c = new CustomAuthentication(apiKey,false);
          var a = authenticationManager.authenticate(c);
              SecurityContextHolder.getContext().setAuthentication(a);
              /*
              You don’t check isAuthenticated() because AuthenticationManager.authenticate()
              only returns authenticated objects or throws an exception.
               */

      }catch (AuthenticationException e) { // when it (apikey throws an exception,
      }  // we catch it, and then we didn't blocked or throw unauthorised error, since next authentication chance
        // below we move to the next filter( basic auth
        filterChain.doFilter(request, response);
    }

    /*
    Every authentication filter that is not guaranteed to run first
     must check the SecurityContext and skip if already authenticated.
     */
}


