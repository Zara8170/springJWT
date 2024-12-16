package com.example.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component // 여기 클래스 빈으로 등록해줘 하는 어노테이션
public class JWTUtil { // 토큰 만들고 암호화 추출하고

  private SecretKey secretKey;

  // 생성자 지정 (factory annotation 써야됨)
  public JWTUtil(@Value("${authen.jwt.secret.key}") String secretKey) {
    this.secretKey = new SecretKeySpec(secretKey.getBytes(),
        Jwts.SIG.HS256.key().build().getAlgorithm());
    // jwts에서 key값을 가져와서 객체 만들고 getalgorithm을 리턴 secretkey객체 만드는 역할만 함
  }

  public String getCategory(String token) {
    return Jwts.parser().verifyWith(this.secretKey).build() // 암호화된 키 객체를 만듬
        .parseSignedClaims(token).getPayload()
        .get("category", String.class); // 토큰을 가져와서 검증을 해서 이름을 추출
  }

  public String getUsername(String token) {
    return Jwts.parser().verifyWith(this.secretKey).build() // 암호화된 키 객체를 만듬
        .parseSignedClaims(token).getPayload()
        .get("username", String.class); // 토큰을 가져와서 검증을 해서 이름을 추출
  }

  public String getRole(String token) {
    return Jwts.parser().verifyWith(this.secretKey).build()
        .parseSignedClaims(token).getPayload().get("role", String.class);
  }

  public Boolean isExpired(String token) { // 토큰 있는지 없는지
    return Jwts.parser().verifyWith(this.secretKey).build()
        .parseSignedClaims(token).getPayload().getExpiration().before(new Date());
  }

  public String CreateJWT(String category,String username, String role, Long expireMs) {
    return Jwts.builder()
        .claim("category", category)
        .claim("username", username)
        .claim("role", role)
        .issuedAt(new Date(System.currentTimeMillis())) // 현재시간
        .expiration(new Date(System.currentTimeMillis() + expireMs))
        .signWith(this.secretKey)
        .compact();
  }
}
// header : 토큰의 종류가 jwt다, 암호화 알고리즘이 있음
// header랑 payload엔 알려져선 안되는 정보는 넣지 않는다. 이 두개를 암호화해서 signed~로 집어 넣어서 검증을 함
// jwt는 단방향임 -> signed~를 통해 header랑 payload를 알 수 없음
