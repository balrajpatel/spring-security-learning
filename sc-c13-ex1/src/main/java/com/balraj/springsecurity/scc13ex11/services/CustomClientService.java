package com.balraj.springsecurity.scc13ex11.services;

import com.balraj.springsecurity.scc13ex11.entities.Client;
import com.balraj.springsecurity.scc13ex11.repositories.ClientRepository;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Getter
@Setter
@Service
public class CustomClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;

    // Client our stored in DB
    // RegisteredClient needed by Spring so we interchange them using the static from methods of Client.

    @Override
    public void save(RegisteredClient registeredClient) {
            clientRepository.save(Client.from(registeredClient));   //save of type client not registeredClient
    }

    @Override
    public RegisteredClient findById(String id) {
        var regClient =clientRepository.findById(Integer.valueOf(id)).orElseThrow();
        return Client.from(regClient);   //return the RegisteredClient type not the Client.
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        var client = clientRepository.findByClient_id(clientId).orElseThrow();
        return Client.from(client);   //return the RegisteredClient type not the Client.
    }
}
