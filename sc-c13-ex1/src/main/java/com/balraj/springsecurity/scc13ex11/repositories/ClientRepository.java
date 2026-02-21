package com.balraj.springsecurity.scc13ex11.repositories;


import com.balraj.springsecurity.scc13ex11.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Integer> {

    @Query("select c from Client c where c.client_id = :client_id")
    Optional<Client> findByClient_id(String client_id);

    // we need these to implement the RegisteredClient;
    // just we need findByUsername in  UserDetailsService so we implement it.


}
