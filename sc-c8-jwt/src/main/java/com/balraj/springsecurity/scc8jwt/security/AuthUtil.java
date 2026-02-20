package com.balraj.springsecurity.scc8jwt.security;

import com.balraj.springsecurity.scc8jwt.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class AuthUtil {
    @Value("${jwt.secret-key}")
    private String jwtSecretKey;

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8 ));
    }


    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }    /*
    What Happens Inside JJWT (HS256)
            When you do:
            Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token);

            JJWT:
            1. Decode Base64
            2. Extract header, payload
            3. Recompute HMAC(secret, header.payload)
            4. Compare signatures
            5. Check expiration
            6. Return Claims

            If anything fails → exception.
     */


    public String generateAccessToken(SecurityUser user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("userId",user.getId().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() +1000*60*60))
                .signWith(getSecretKey())
                .compact();

    }

    public String getUserNameFromToken(String token) {
        return extractAllClaims(token).getSubject();


    }

    private boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }


    public boolean validateToken(String token, UserDetails userDetails) {
        String username = getUserNameFromToken(token);  // while using this verification of token is already done,
        return userDetails.getUsername().equals(username) &&!isTokenExpired(token);

        /*
        validateToken checks:
        1️ Username matches DB user
        2️ Token is not expired
         */

    }



}
