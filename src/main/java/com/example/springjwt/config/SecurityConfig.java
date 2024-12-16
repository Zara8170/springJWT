package com.example.springjwt.config;

import com.example.springjwt.component.CustomAccessDeniedHandler;
import com.example.springjwt.component.CustomAuthenticationEntryPoint;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.JwtFilter;
import com.example.springjwt.jwt.LoginFilter;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final AuthenticationConfiguration authenticationConfiguration; //addFilterAt에 manager을 넣기 위해 불러오고
  private final JWTUtil jwtUtil; // LoginFilter에 생성자가 두개가 되서 여기서도 추가해야됨
  private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
  private final CustomAccessDeniedHandler customAccessDeniedHandler;

  @Bean
  public AuthenticationManager authenticationManager( //Bean으로 정의해서 매니저를 만들고
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public LogoutSuccessHandler logoutHandler() {
    return (request, response, authentication) -> {
      response.setStatus(HttpStatus.OK.value());
      response.getWriter().write("logout success");
    };
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable())
        .formLogin(formLogin -> formLogin.disable()) // 세션방식에서 사용
        .httpBasic(httpBasic -> httpBasic.disable()) // 세션방식, Http basic Auth 기반으로 로그인 인증창이 뜸
        .authorizeHttpRequests(auth ->
            auth.requestMatchers("/", "/login", "/join","/reissue").permitAll()
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated());

    http.cors(cors ->
        cors.configurationSource(request -> {
          CorsConfiguration config = new CorsConfiguration();
          config.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:3001"));
          config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
          config.setAllowCredentials(true);
          // 쿠키, Authorization 인증 헤더, TLS client certificates(증명서)를 내포하는 자격 인증 정보
          // 클라이언트,서버 모두 credetial 부분을 true로 설정해주어야 쿠키나 인증 헤더를 포함시킬 수 있다
          config.addAllowedHeader("*"); // 클라에서 보내는 헤더는 모두 허용한다.
          config.addExposedHeader("Authorization"); // 내가 보낸 헤더를 너가 까도 된다
          return config;
        }));

    http.sessionManagement(session ->
        session.sessionCreationPolicy(
            SessionCreationPolicy.STATELESS)); // 세션 만드는 정책으로 어떤 세션 정보도 서버에 저장하지 않는다.

    http.addFilterBefore(new JwtFilter(this.jwtUtil), LoginFilter.class); // loginfilter 전에 실행

    http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil),
        UsernamePasswordAuthenticationFilter.class); // 로그인 필터 집어넣는 코드 // 위에서 만든 매니저를 집어 넣는다. // LoginFilter에서 jwtUtil 생성자 호출을 위해 추가

    http.exceptionHandling(exception -> {
      exception.authenticationEntryPoint(customAuthenticationEntryPoint);
      exception.accessDeniedHandler(customAccessDeniedHandler);
    });

    return http.build();
  }
}
