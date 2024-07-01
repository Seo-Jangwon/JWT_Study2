package com.practice.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.practice.jwt.entity.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    // application.properties 또는 application.yml에서 설정된 JWT 비밀키를 로드
    @Value("${jwt.secret}")
    private String secret;

    // 액세스 토큰 만료 시간 로드
    @Value("${jwt.accessExpiration}")
    private Long accessExpiration;

    // 리프레시 토큰 만료 시간 로드
    @Value("${jwt.refreshExpiration}")
    private Long refreshExpiration;

    // 로깅을 위한 Logger 인스턴스 생성
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    // 비밀키를 Key 객체로 변환하여 반환
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    // JWT 토큰에서 사용자 이름 추출
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            logger.error("Failed to extract username from token", e);
            return null;
        }
    }

    // JWT 토큰에서 만료 시간 추출
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // JWT 토큰에서 특정 클레임 추출
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // JWT 토큰에서 모든 클레임 추출
    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey()) // 서명 키 설정
                    .build()
                    .parseClaimsJws(token) // 토큰 파싱
                    .getBody();
        } catch (ExpiredJwtException e) {
            logger.error("Token expired", e);
            throw new RuntimeException("Token expired", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid token", e);
            throw new RuntimeException("Invalid token", e);
        } catch (SignatureException e) {
            logger.error("Invalid token signature", e);
            throw new RuntimeException("Invalid token signature", e);
        } catch (IllegalArgumentException e) {
            logger.error("Token claims are empty", e);
            throw new RuntimeException("Token claims are empty", e);
        }
    }

    // JWT 토큰이 만료되었는지 확인
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 사용자 객체를 기반으로 액세스 토큰 생성
    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, user.getUsername(), accessExpiration);
    }

    // 사용자 객체를 기반으로 리프레시 토큰 생성
    public String generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, user.getUsername(), refreshExpiration);
    }

    // 클레임, 주제, 만료 시간을 기반으로 JWT 토큰 생성
    private String createToken(Map<String, Object> claims, String subject, Long expiration) {
        return Jwts.builder()
                .setClaims(claims) // 클레임 설정
                .setSubject(subject) // 주제 설정
                .setIssuedAt(new Date(System.currentTimeMillis())) // 발행 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 만료 시간 설정
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // 서명 설정
                .compact(); // 토큰 생성
    }

    // JWT 토큰이 유효한지 확인
    public Boolean validateToken(String token, User user) {
        final String username = extractUsername(token);
        return (username != null && username.equals(user.getUsername()) && !isTokenExpired(token));
    }
}
