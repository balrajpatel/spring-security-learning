package com.balraj.springsecurity.scc13ex11.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Consumer;

public class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
    // “This class will receive an OAuth2AuthorizationCodeRequestAuthenticationContext and do something with it.”
    //consumer consumes this obj  and do something with it.

    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext context) {
        // 1. Cast the generic Authentication object to the specific Token type
        OAuth2AuthorizationCodeRequestAuthenticationToken authentication = context.getAuthentication();

        // 2. Get the registered client from the context
        RegisteredClient registeredClient = context.getRegisteredClient();

        // 3. Now you can access the Authorization Request and its Redirect URI
        String requestedUri = authentication.getRedirectUri();

        // 4. Validate against the registered URIs
        if (requestedUri != null && !registeredClient.getRedirectUris().contains(requestedUri)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }
    }
}
