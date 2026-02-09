package com.balraj.springsecurity.scc2ex1.repositories;

import com.balraj.springsecurity.scc2ex1.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}
