package ru.kata.spring.boot_security.demo.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.model.User;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;
import java.util.List;

public interface UserService extends UserDetailsService {

    List<User> getAllUsers();

    void save(User user);

    User getById(Long id);

    User findByUsername(String username);

    void delete(Long id);

    void update(Long id, User user) throws EntityNotFoundException;

    User getAllRoles();
}
