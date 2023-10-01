package com.goit.config;

import com.goit.entity.Role;
import  com.goit.entity.User;
import  com.goit.repo.RoleRepository;
import  com.goit.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;



@Slf4j
@Component
@RequiredArgsConstructor
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        if (alreadySetup || userRepository.findAll().iterator().hasNext()) {
            return;
        }

        // Create user roles
        var userRole = createRoleIfNotFound(Role.ROLE_USER);
        var adminRole = createRoleIfNotFound(Role.ROLE_ADMIN);

        // Create users
        createUserIfNotFound("user@javachinna.com", passwordEncoder.encode("user@@"), // "user"
                userRole, "User");
        createUserIfNotFound("admin@javachinna.com", passwordEncoder.encode("admin@"), // "admin"
                adminRole, "Administrator");
        alreadySetup = true;
    }


    @Transactional
   public void createUserIfNotFound(final String email, final String password, final Role role, final String displayName) {
        User user = userRepository.findByEmailIgnoreCase(email);
        if (user == null) {
            user = new User(email, password);
            user.addRole(role);
            user.setEnabled(true);
            user.setDisplayName(displayName);
            userRepository.save(user);
        }
    }

    @Transactional
    public Role createRoleIfNotFound(final String name) {
        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
            role = roleRepository.save(role);
        }
        return role;
    }
}
