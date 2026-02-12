package com.balraj.springsecurity.scc8jwt.security;

import com.balraj.springsecurity.scc8jwt.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Log4j2      // form lombok for logging.
public class JwtAuthFilter extends OncePerRequestFilter {
    private final CustomUserDetailsService customUserDetailsService;
    private final AuthUtil authUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        log.info("incoming request:{}", request.getRequestURI());

        // if no authHeader continue filter chain
        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        //token extract from authHeader
        String token = authHeader.substring(7);


        try {
            String username = authUtil.getUserNameFromToken(token);

            //load user from DB via CustomUserDetailsService
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {


                SecurityUser securityUser = (SecurityUser) customUserDetailsService.loadUserByUsername(username);
                // here userDetails is of type SecurityUser

                log.info("User authenticated: {}", username);

                // validate Token
                if (authUtil.validateToken(token, securityUser)) {
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(securityUser,
                                    null, securityUser.getAuthorities());
                    //since we want to set the authentication in springSecurityContext after jwt verification;

                    SecurityContextHolder.getContext().setAuthentication(authentication);

                }
                ;

            }
        }catch (io.jsonwebtoken.ExpiredJwtException e) {

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token Expired");
            return; // stop filter chain

        } catch (Exception e) {

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Invalid Token");
            return;
        }

        filterChain.doFilter(request, response);


    }
}
