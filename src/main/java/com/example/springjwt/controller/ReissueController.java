package com.example.springjwt.controller;

import com.example.springjwt.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class ReissueController {

  private final JWTUtil jwtUtil;

  @PostMapping(value = "/reissue")
  public ResponseEntity<String> reissue(HttpServletRequest request, HttpServletResponse response) {
    String refresh = null;
    Cookie[] cookies = request.getCookies(); // 쿠키들을 가져와서
    for (Cookie cookie : cookies) { // 반복문 돌려서
      if (cookie.getName().equals("refresh")) { //refresh랑 같으면
        refresh = cookie.getValue(); // 쿠키 값을 가진다
        break;
      }
    }

    if (refresh == null) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh 토큰 null");
    }

    try {
      this.jwtUtil.isExpired(refresh);

    } catch (ExpiredJwtException ex) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("refresh 토큰 유효기간 만료");
    }

    String category = jwtUtil.getCategory(refresh);
    if (!category.equals("refresh")) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("유효하지 않은 refresh 토큰");
    }

    String username = this.jwtUtil.getUsername(refresh);
    String role = this.jwtUtil.getRole(refresh);

    String newAccessToken = this.jwtUtil.CreateJWT("access", username, role, 5000L);
    response.addHeader("Authorization", "Bearer " + newAccessToken);
    response.setCharacterEncoding("UTF-8");
    return ResponseEntity.status(HttpStatus.OK).body("새 토큰 발급 성공");
  }
}
