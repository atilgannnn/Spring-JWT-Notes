package com.tpe.service;

import com.tpe.controller.dto.*;
import com.tpe.domain.*;
import com.tpe.domain.enums.*;
import com.tpe.exception.*;
import com.tpe.repository.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.security.crypto.password.*;
import org.springframework.stereotype.*;

import java.util.*;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    public void registerUser(RegisterRequest registerRequest) {

        if(userRepository.existsByUserName(registerRequest.getUserName())) {
            throw new ConflictException("Girdiğiniz username kullanımda");
        }
        Role role = roleRepository.findByName(UserRole.ROLE_STUDENT).orElseThrow(
                ()-> new ResourceNotFoundException("Role bilgisi bulunamadı")
        );
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        User user = new User();
        user.setFirstName(registerRequest.getFirstName());
        user.setLastName(registerRequest.getLastName());
        user.setUserName(registerRequest.getUserName());
        user.setRoles(roles);
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

        userRepository.save(user);

    }
}
