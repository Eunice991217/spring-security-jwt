package com.example.securityprac.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // 객체 키를 저장할 SecretKey
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        // 이 key 는 jwt 에서 객체 타입으로 저장하면서 그 키를 암호화를 진행 해야 함
        // String type 으로 받은 시크릿 키를 객체 변수로 암호화
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 검증 진행
    public String getUsername(String token) {
        // 토큰 검증 verifyWith : 내가 가지고 있는 시크릿 키가 서버에서 생성된게 맞는지
        // parseSignedClaims : 클레임 파싱 (클레임 정보 추출) JWT의 payload 부분에 들어있는 정보
        // getPayload : 특정한 데이터 가져오기 (username 이라는 키를 가지고 있고, String type 으로 가져옴)
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    // 토큰 판단용
    public String getCategory(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 토큰 생성
    public String createJwt(String category, String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("category", category)
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs * 1000))
                .signWith(secretKey) // 시크릿 키를 가지고 암호화 진행
                .compact(); // 토큰 컴팩
    }

}
