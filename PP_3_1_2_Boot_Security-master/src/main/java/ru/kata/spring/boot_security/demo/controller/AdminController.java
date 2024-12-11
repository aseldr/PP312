package ru.kata.spring.boot_security.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepository;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.security.Principal;
import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private UserService userService;

    @Autowired
    public void adminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public String adminHomeAndAllUsers(Model model, Principal principal) {
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("principal", principal);
        model.addAttribute("userPrincipal", userService.getById(Long.valueOf(principal.getName())));
        return "index";
    }

    @PostMapping("/delete") // Изменено: добавлен путь для удаления
    public String delete(@RequestParam("id") Long id) {
        userService.delete(id);
        return "redirect:/admin";
    }

    @PostMapping("/edit") // Изменено: добавлен путь для редактирования
    public String adminHomePost(@RequestParam("id") Long id, @RequestParam("action") String action) {
        if (action.equals("delete")) {
            userService.delete(id);
        } else if (action.equals("edit")) {
            return "redirect:/admin/update?id=" + id;
        }
        return "redirect:/admin";
    }

    @GetMapping("/create")
    public String createUserForm(Model model) {
        model.addAttribute("user", new User());
        UserRepository userRepository = null; // Обратите внимание, что userRepository не инициализирован
        model.addAttribute("allRoles", userRepository.findAll());
        return "create";
    }

    @PostMapping("/create")
    public String createUser(@ModelAttribute("user") User user, @RequestParam("authorities") List<String> roles) {
        userService.save(user);
        return "redirect:/admin";
    }

    @GetMapping("/update")
    public String edit(Model model, @RequestParam("id") Long id) {
        User user = userService.getById(id);
        model.addAttribute("user", user);
        model.addAttribute("userRole", user.getAuthorities());
        model.addAttribute("isAdmin", user.getAuthorities().contains("ROLE_ADMIN"));
        return "update";
    }

    @PostMapping("/update")
    public String update(@ModelAttribute("user") User user, @RequestParam("id") Long id, @RequestParam("role") List<String> roles) {
        userService.update(id, user);
        return "redirect:/admin";
    }
}