package com.example.secureauthapp.controller;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.secureapp.service.CustomUserDetailsService;

@Controller
public class WebsiteController {

    private final CustomUserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;

    public GreetingController(CustomUserDetailsService userDetailsService, AuthenticationManager authenticationManager) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/greet")
    public String greet(Model model) {
        // Get the authenticated user's username
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        System.out.println("Username from context "+username);

        // Add the username to the model
        model.addAttribute("username", username);

        // Return the Thymeleaf template name
        return "greet";
    }

    @GetMapping("/login")
    public String login() {
        return "login"; // Returns the login.html template
    }

    @GetMapping("/register")
    public String register() {
        return "register"; // Returns the register.html template
    }

    // POST endpoint to handle user registration and auto-login
    @PostMapping("/register")
    public String registerUser(
            @RequestParam String username, // Username from the form
            @RequestParam String password // Password from the form
    ) {
        // Register the user by storing their details in the HashMap
        try {
            userDetailsService.registerUser(username, password);
        } catch (Exception userExistsAlready) {
            // Redirect to the /register endpoint
            return "redirect:/register?error";
        }

        // Authenticate the user programmatically
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );

        // Set the authentication in the SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Redirect to the /login endpoint
        return "redirect:/login?success";
    }
}
