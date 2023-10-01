package com.goit.service;

import com.goit.dto.SignUpRequest;
import com.goit.entity.User;
import com.goit.exception.UserAlreadyExistAuthenticationException;

public interface UserService {

    User findUserByEmail(String email);

    User registerNewUser(SignUpRequest signUpRequest) throws UserAlreadyExistAuthenticationException;
}
