package com.springauth.service.impl;

import org.springframework.stereotype.Service;

import com.springauth.model.User;
import com.springauth.service.UserRepository;

@Service
public class UserRepositoryImpl implements UserRepository {

	@Override
	public User findByUsername(String username) {

		return new User(1l, "kalees", "password", "USER");
	}

}
