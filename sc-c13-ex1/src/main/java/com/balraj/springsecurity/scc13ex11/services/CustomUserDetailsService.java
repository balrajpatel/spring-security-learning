package com.balraj.springsecurity.scc13ex11.services;

import com.balraj.springsecurity.scc13ex11.entities.User;
import com.balraj.springsecurity.scc13ex11.model.SecurityUser;
import com.balraj.springsecurity.scc13ex11.repositories.UserRepository;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;


@AllArgsConstructor
@Getter
@Setter
@Service   // here we provided the CustomUserDetailsService to the spring instead of InMemory.
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
        return new SecurityUser(user);
    }
}
