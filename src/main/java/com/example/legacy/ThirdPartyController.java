package com.example.legacy;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/third-party/v1")
public class ThirdPartyController {
    @GetMapping("/info")
    public String info(Principal principal) {
        return "Third-party : " + principal.getName();
    }
}
