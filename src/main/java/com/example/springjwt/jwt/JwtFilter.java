package com.example.springjwt.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

  private final JWTUtil jwtUtil;

  @Override // 토큰을 분리해서 내가 발급한 토큰인지 확인하는 필터
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String authToken = request.getHeader("Authorization");
    if (authToken == null || !authToken.startsWith("Bearer ")) { // 원하는 토큰이 없으면 다음 필터로 넘긴다.
      System.out.println("token null");
      filterChain.doFilter(request, response);
      return;
    }

//    String token = authToken.substring(7); // Bearer 뒤
    String token = authToken.split(" ")[1]; // 공백 기준으로 나눔
    try {
      jwtUtil.isExpired(token); // 만료가 되면 exception 발생 만료 됬는지 확인
    } catch(ExpiredJwtException ex) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
      response.setCharacterEncoding("UTF-8");
      System.out.println("만료된 토큰");
      response.getWriter().write("만료된 토큰입니다");
      return;
    }

    String category= jwtUtil.getCategory(token); // 카테고리 처리
    if(!category.equals("access")) {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.setCharacterEncoding("UTF-8");
      System.out.println("허용되지 않은 토큰");
      response.getWriter().write("허용되지 않은 토큰입니다.");
    }

    // 임시 세션 정보를 만들어야됨, 필요한것: payload에 있던 정보들(username, role etc...)
    String username = jwtUtil.getUsername(token);
    String role = jwtUtil.getRole(token);

    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority(role));

    User user = new User(username, "", authorities);
    Authentication auth = new UsernamePasswordAuthenticationToken(user, null, authorities);

    SecurityContextHolder.getContext().setAuthentication(auth); // 임시 세션 객체 생성 정보 필요할때 이 친구 부름
    filterChain.doFilter(request, response);
  }
}
