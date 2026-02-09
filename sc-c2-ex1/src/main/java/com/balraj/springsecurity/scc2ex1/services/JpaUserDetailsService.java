package com.balraj.springsecurity.scc2ex1.services;

import com.balraj.springsecurity.scc2ex1.repositories.UserRepository;
import com.balraj.springsecurity.scc2ex1.security.SecurityUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username)  {
         var user = userRepository.findByUsername(username);

        return user.map(SecurityUser::new).orElseThrow(()->new UsernameNotFoundException("User not found"+username));
    }
}
