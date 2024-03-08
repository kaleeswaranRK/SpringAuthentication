package com.springauth.service;

import org.springframework.stereotype.Repository;

import com.springauth.model.User;

@Repository
public interface UserRepository {
    User findByUsername(String username);
}

