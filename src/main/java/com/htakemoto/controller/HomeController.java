package com.htakemoto.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value="")
public class HomeController {
    
    @RequestMapping("/")
    String home() {
        return "Welcome to home!";
    }
    
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    String developers() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return "Hello, " + username + "!";
    }
    
    @RequestMapping(value = "/manager", method = RequestMethod.GET)
    String managers() {
        return "Hello manager!";
    }
    
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    String admin() {
        return "Hello admin!";
    }
}
