package com.balraj.springsecurity.scc8jwt.service;

import com.balraj.springsecurity.scc8jwt.repositores.JpaUserRepository;
import com.balraj.springsecurity.scc8jwt.security.SecurityUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Service
@AllArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final JpaUserRepository jpaUserRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = jpaUserRepository.findByUsername(username);
        return user.map(SecurityUser::new).orElseThrow(()->new UsernameNotFoundException("User Not Found"+ username));
    }
}
