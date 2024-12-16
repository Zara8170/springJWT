package com.example.springjwt.controller;

import com.example.springjwt.data.dto.AuthenDTO;
import com.example.springjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class JoinController {

  private final JoinService joinService;

  @PostMapping(value = "/join")
  public ResponseEntity<String> join(@RequestBody AuthenDTO authenDTO) {
    if (joinService.join(authenDTO)) {
      return ResponseEntity.status(HttpStatus.CREATED).body("가입 성공");
    }

    return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 있는 아이디 입니다.");
  }

  @GetMapping(value = "/admin")
  public ResponseEntity<String> admin() {
    return ResponseEntity.status(HttpStatus.OK).body("관리자입니다.");
  }

}
