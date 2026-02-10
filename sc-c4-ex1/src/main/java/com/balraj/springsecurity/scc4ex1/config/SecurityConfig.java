package com.balraj.springsecurity.scc4ex1.config;

import com.balraj.springsecurity.scc4ex1.config.filters.ApiKeyFilter;
import com.balraj.springsecurity.scc4ex1.config.managers.CustomAuthenticationManager;
import com.balraj.springsecurity.scc4ex1.config.providers.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig {

   /*@Bean
   AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
       return config.getAuthenticationManager();
   }*/

     // add bean of default manager will make no diff for basic auth ,since internally it uses this
    //and for apiKey we internally provided our own authentication provider and manager
    //so it will not effect the apikey authentication;

/*@Bean
CustomAuthenticationProvider customAuthenticationProvider() {
       return new CustomAuthenticationProvider("df");
}
here if i add a bean of any custom provider or manager, spring auto configuration
will disable itself's provider or manager  of basic auth
 */

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // For demo only. Use BCrypt in prod.
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   @Value("${the.secret}") String secretKey) throws Exception {

        /* * MANUAL WIRING (The "Hidden" Approach)
         * 1. Create Provider with the key
         * 2. Create Manager with the Provider
         * 3. Create Filter with the Manager
         * * Since these are created with 'new', Spring's global Basic Auth
         * doesn't know they exist, so it won't break!
         */
        CustomAuthenticationProvider customProvider = new CustomAuthenticationProvider(secretKey);
        CustomAuthenticationManager customManager = new CustomAuthenticationManager(customProvider);
        ApiKeyFilter apiKeyFilter = new ApiKeyFilter(customManager);

        return http
                .httpBasic(Customizer.withDefaults()) // Spring manages this itself now
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(apiKeyFilter, BasicAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated()
                )
                .build();
    }
}
/*
All DSL methods must use the lambda-based configuration style.
So methods like:
http.httpBasic()
http.csrf()
http.cors()
were deprecated only in their no-arg form, to avoid ambiguity and hidden defaults.
This is an API cleanup
 */