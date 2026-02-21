package com.balraj.springsecurity.scc13ex11.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.stream.Collectors;

@Getter
@Setter
@Entity
@Table( name="clients_auth")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String client_id;
    private String secret;
    private String scope;
    private String auth_method;
    private String grant_type;
    private String redirect_uri;


    // these static method required in the Custom RegisteredClientRepository implementation

    public static Client from(RegisteredClient registeredClient){
        Client client = new Client();    // you could have annotated @Builder and used Builder Pattern.
        client.setClient_id(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setScope(registeredClient.getScopes().stream().findAny().get());
        client.setRedirect_uri(registeredClient.getRedirectUris().stream().findAny().get());
        client.setAuth_method(registeredClient.getClientAuthenticationMethods().stream().findAny().get().getValue());
        client.setGrant_type(registeredClient.getAuthorizationGrantTypes().stream().findAny().get().getValue());
        return client;
    }

    public static RegisteredClient from(Client client){
        RegisteredClient client1 = RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClient_id())
                .clientSecret(client.getSecret())
                .redirectUri(client.getRedirect_uri())
                .scope(client.getScope())
                .authorizationGrantType(new AuthorizationGrantType(client.getGrant_type()))
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuth_method()))
                .build();
        return client1;
    }
}
