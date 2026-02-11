package com.balraj.springsecurity.scc7ex1.security;

import org.springframework.stereotype.Component;

@Component
public class Test4ControllerCondition {
    // you can get the authentication object using the context
    public boolean condition(){
        return true;
    }
}
