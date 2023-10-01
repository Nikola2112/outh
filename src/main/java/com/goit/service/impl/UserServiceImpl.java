package com.goit.service.impl;

import com.goit.dto.SignUpRequest;
import com.goit.entity.Role;
import com.goit.entity.User;
import com.goit.exception.UserAlreadyExistAuthenticationException;
import com.goit.repo.RoleRepository;
import com.goit.repo.UserRepository;
import com.goit.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public User findUserByEmail(final String email) {
		return userRepository.findByEmailIgnoreCase(email);
	}

	@Override
	@Transactional()
	public User registerNewUser(final SignUpRequest signUpRequest) throws UserAlreadyExistAuthenticationException {
		if (userRepository.existsByEmailIgnoreCase(signUpRequest.getEmail())) {
			throw new UserAlreadyExistAuthenticationException("User with email id " + signUpRequest.getEmail() + " already exist");
		}
		User user = buildUser(signUpRequest);
		user = userRepository.save(user);
		userRepository.flush();
		return user;
	}

	private User buildUser(final SignUpRequest signUpRequest) {
		User user = new User();
		user.setDisplayName(signUpRequest.getDisplayName());
		user.setEmail(signUpRequest.getEmail());
		user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
		user.addRole(roleRepository.findByName(Role.ROLE_USER));
		user.setEnabled(true);
		return user;
	}
}
