package com.example.springjwt.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class LoginFilter extends
    UsernamePasswordAuthenticationFilter { // 세션방식에서 사용되는 filter 원래하던 방식을 block 시키고 jwt방식으로 교체함

  private final AuthenticationManager authenticationManager; // 이놈이 매니저 AuthenticationConfiguration이 만듬

  private final JWTUtil jwtUtil;

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response)
      throws AuthenticationException {
    String username = obtainUsername(request);
    String password = obtainPassword(request);
    // 매니저한테 시키는데 매니저 바구니가 있음
    UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
        username, password, null);

    return authenticationManager.authenticate(authRequest); // 매니저한테 바구니 넘겨주기
  }

  @Override // 여기서 토큰 생성해서 넘길거임
  public void successfulAuthentication(HttpServletRequest req,
      HttpServletResponse res, FilterChain chain, Authentication auth) throws IOException {
    UserDetails userDetails = (UserDetails) auth.getPrincipal();
    String username = userDetails.getUsername();

    Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities(); // List도 가능
    Iterator<? extends GrantedAuthority> iterator = authorities.iterator(); // iterator를 가져옴
    GrantedAuthority grantedAuthority = iterator.next(); // 첫번째 role을 가져옴
    String role = grantedAuthority.getAuthority(); // role의 문자열 가져옴

    String acceessToken = this.jwtUtil.CreateJWT("acceess",username, role,
        5000L); // 토큰 생성 -> 주로 header에 전달

    String refreshToken = this.jwtUtil.CreateJWT("refresh",username, role, 24 * 60 * 60 * 1000L); // ms 단위



    res.addHeader("Authorization", "Bearer " + acceessToken); // 헤더 추가 Bearer
    res.addCookie(createCookie("refresh", refreshToken));
    res.setCharacterEncoding("UTF-8");
    res.getWriter().write("로그인 성공");
  }

  private Cookie createCookie(String key, String value) {
    Cookie cookie = new Cookie(key, value);
    cookie.setPath("/");
    cookie.setHttpOnly(true); // 자바스크립트는 접근할 수 없다.
    cookie.setMaxAge(60 * 60 * 24); // 초단위
    return cookie;
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest req,
      HttpServletResponse res, AuthenticationException failed)
      throws IOException, ServletException {
    Map<String, String> responseData = new HashMap<>();
    responseData.put("message", "계정정보가 틀립니다");

    ObjectMapper objectMapper = new ObjectMapper();
    String jsonmessage = objectMapper.writeValueAsString(responseData);

    res.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 error
    res.setContentType("application/json");
    res.setCharacterEncoding("UTF-8");
    res.getWriter().write(jsonmessage);
  }

}
