package com.example.legacy;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/user")
public class UserController {
    @GetMapping("/info")
    public String info(Principal principal) {
        return "Username : " + principal.getName();
    }
}
