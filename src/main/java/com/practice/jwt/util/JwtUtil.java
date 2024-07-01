package com.practice.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.practice.jwt.entity.User;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;  // JWT 서명에 사용할 비밀 키. application.properties 파일에서 값을 가져옴.

    @Value("${jwt.accessExpiration}")
    private Long accessExpiration;  // Access Token의 만료 시간. application.properties 파일에서 값을 가져옴.

    @Value("${jwt.refreshExpiration}")
    private Long refreshExpiration;  // Refresh Token의 만료 시간. application.properties 파일에서 값을 가져옴.

    // JWT 토큰에서 사용자 이름(Username)을 추출하는 메서드
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // JWT 토큰에서 만료 날짜를 추출하는 메서드
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // JWT 토큰에서 특정 클레임을 추출하는 일반적인 메서드
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // JWT 토큰에서 모든 클레임을 추출하는 메서드
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    // JWT 토큰이 만료되었는지 확인하는 메서드
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 주어진 사용자 정보를 바탕으로 Access Token을 생성하는 메서드
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();  // 클레임을 담을 맵 생성
        return createToken(claims, user.getUsername(), accessExpiration);  // Access Token 생성
    }

    // 주어진 사용자 정보를 바탕으로 Refresh Token을 생성하는 메서드
    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();  // 클레임을 담을 맵 생성
        return createToken(claims, user.getUsername(), refreshExpiration);  // Refresh Token 생성
    }

    // 클레임과 주제, 만료 기간을 바탕으로 JWT 토큰을 생성하는 메서드
    private String createToken(Map<String, Object> claims, String subject, Long expiration) {
        return Jwts.builder()
                .setClaims(claims)  // 클레임 설정
                .setSubject(subject)  // 주제(보통 사용자 이름) 설정
                .setIssuedAt(new Date(System.currentTimeMillis()))  // 토큰 발행 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + expiration))  // 토큰 만료 시간 설정
                .signWith(SignatureAlgorithm.HS256, secret)  // 서명 알고리즘과 비밀 키 설정
                .compact();  // 토큰 생성
    }

    // 주어진 JWT 토큰이 유효한지 확인하는 메서드
    public Boolean validateToken(String token, User user) {
        final String username = extractUsername(token);  // 토큰에서 사용자 이름 추출
        return (username.equals(user.getUsername()) && !isTokenExpired(token));  // 사용자 이름 일치 여부와 토큰 만료 여부 확인
    }
}

