package com.balraj.springsecurity.scc5ex1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                //is endpoint  level authorization
                //anyRequest().permitAll() ====  for any request, permit ,
                                            //  but if authentication used, then authentication applied, since
                                            //since authentication comes  before authorization
                // denyAll() for denying all request, same logic if authentication used

                // .hasAuthority(" ")  ,name itself access it;
                // .hasAnyAuthority( ... , ... , ...)   any of parameter authority user has can access;
                // .hasRole()
                // .hadAnyRole(.... , ....,....)
                // .access(  spel);  spel means specific expression language to give authorization rules it must return boolean
                // so that access can grant or not grant
                .build();
    }
    // authentication means user is known, authorisation means what user have access, or what it can acquire
    // so end points level authorization means it can access the endpoint or not based on it authority;


    // authority usually represents actions(verb) it can perform
    //role means the badge (something you are) and based on it , you can perform actions,
    //so role can have multiple authorities (actions)

    // in java internally roles are  stored as  ROLE_.... as  authorities.
    //roles.("MANAGER")  is same as .authorities("ROLE_MANAGER")
    // since internally roles convert to authority with ROLE prefix
    //since both implements grantedAuthority;

        //  .authorizeHttpRequests(auth->auth.(matcher method .+ authorization rule ) // ENDPOINT LEVEL AUTHORISATION
        //1st which matcher method to use   (anyRequest(), mvcMatchers(), antMatchers(), regexMatchers();
        //2nd how to apply the different authorization rule;

    @Bean
    public UserDetailsService userDetailsService() {
        var uds = new InMemoryUserDetailsManager();
        var user1 = User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .authorities("read") // equivalent with  ROLE_ADMIN authority;
                .build();
        var user2 = User.withUsername("user2")
                .password(passwordEncoder().encode("password2"))
                .authorities("write")
                .build();
        uds.createUser(user1);
        uds.createUser(user2);
        return uds;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
