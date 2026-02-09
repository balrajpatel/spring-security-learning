package com.balraj.springsecurity.scc2ex1.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Entity
@Table(name="users")
@Getter
@Setter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;

    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name= "users_authorities",
    joinColumns = @JoinColumn(name="userId"),
    inverseJoinColumns = @JoinColumn(name = "authorityId"))
    private Set<Authority> authorities;


    // fetch type  = eager,
    //because when the security fetched te user from userDetailsService as (transaction)
    // the session is ended, and after that in new  session authorities are accessed,
    // so it gave error;

}
