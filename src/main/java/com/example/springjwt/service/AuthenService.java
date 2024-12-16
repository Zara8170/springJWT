package com.example.springjwt.service;

import com.example.springjwt.data.entity.AuthenEntity;
import com.example.springjwt.data.repository.AuthenEntityRepository;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenService implements UserDetailsService {

  private final AuthenEntityRepository authenEntityRepository;

  @Override // LoginFilter에 있는 attemptAuthentication 처리하는 메서드
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    AuthenEntity authenEntity = authenEntityRepository.findByUsername(username);
    if (authenEntity == null) {
      throw new UsernameNotFoundException(username);
    }

    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority(authenEntity.getRole()));

    return new User(authenEntity.getUsername(), authenEntity.getPassword(), authorities);
  }
}
