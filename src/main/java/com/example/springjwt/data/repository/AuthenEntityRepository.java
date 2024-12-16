package com.example.springjwt.data.repository;

import com.example.springjwt.data.entity.AuthenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AuthenEntityRepository extends JpaRepository<AuthenEntity, Integer> {

  AuthenEntity findByUsername(String username);
  Boolean existsByUsername(String username);

}
