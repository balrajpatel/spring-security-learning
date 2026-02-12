package com.balraj.springsecurity.scc8jwt.repositores;


import com.balraj.springsecurity.scc8jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface JpaUserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

}
