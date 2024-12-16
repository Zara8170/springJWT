package com.example.springjwt.component;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    Map<String, Object> responseData = new HashMap<>();
    responseData.put("error", "Unauthorized");
    responseData.put("message", "먼저 로그인하고 시도하세요");

    ObjectMapper objectMapper = new ObjectMapper();
    String jsonmessage = objectMapper.writeValueAsString(responseData);
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
    response.getWriter().write(jsonmessage);
  }
}
