package com.goit.repo;

import com.goit.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
