package com.example.springjwt.service;

import com.example.springjwt.data.dto.AuthenDTO;
import com.example.springjwt.data.entity.AuthenEntity;
import com.example.springjwt.data.repository.AuthenEntityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
@Service
public class JoinService {

  private final AuthenEntityRepository authenEntityRepository;
  private final PasswordEncoder passwordEncoder;

  public boolean join(AuthenDTO authenDTO) {
    if (!authenEntityRepository.existsByUsername(authenDTO.getUsername())) {
      String password = passwordEncoder.encode(authenDTO.getPassword());
      AuthenEntity authenEntity = AuthenEntity.builder()
          .username(authenDTO.getUsername())
          .password(password)
          .role("ROLE_USER")
          .build();
      authenEntityRepository.save(authenEntity);
      return true;
    }
    return false;
  }

}
