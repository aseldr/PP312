package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import ru.kata.spring.boot_security.demo.configs.SuccessUserHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/login")
public class LoginController {


    private final AuthenticationManager authenticationManager;
    private final SuccessUserHandler successUserHandler;


    @Autowired
    public LoginController(AuthenticationManager authenticationManager, SuccessUserHandler successUserHandler) {
        this.authenticationManager = authenticationManager;
        this.successUserHandler = successUserHandler;
    }

    @GetMapping
    public String loginForm() {
        return "/login";
    }

    @PostMapping
    public String login(@RequestParam("email") String email, @RequestParam("password") String password, Model model, HttpServletRequest request, HttpServletResponse response) {

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(email, password);

        try {
            Authentication authentication = authenticationManager.authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            successUserHandler.onAuthenticationSuccess(request, response, authentication);
            return null;
        } catch (BadCredentialsException | IOException e) {
            model.addAttribute("error", "Invalid email or password");
            return "login";
        }
    }
}