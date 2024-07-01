package com.practice.jwt.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.practice.jwt.entity.User;
import com.practice.jwt.service.UserService;
import com.practice.jwt.util.JwtUtil;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;  // UserService를 자동으로 주입받음.

    @Autowired
    private JwtUtil jwtUtil;  // JwtUtil을 자동으로 주입받음.

    @Autowired
    private PasswordEncoder passwordEncoder;  // PasswordEncoder를 자동으로 주입받음.

    // 회원가입 요청을 처리하는 메서드
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody User user) {
        System.out.println("==========signup");
        Optional<User> existingUser = userService.findOptionalByUsername(user.getUsername());
        
        if (existingUser.isPresent()) {  
            return ResponseEntity.badRequest().body("Username already exists");  
        }
        
        User savedUser = userService.save(user);
        return ResponseEntity.ok(savedUser);
    }

    // 로그인 요청을 처리하는 메서드
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        // 사용자 이름으로 기존 사용자 정보를 찾음.
        User existingUser = userService.findByUsername(user.getUsername());  
        // 사용자 정보가 없거나 비밀번호가 일치하지 않으면 400 Bad Request 응답을 반환함.
        if (existingUser == null || !passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid username or password");  
        }
        // Access Token과 Refresh Token 생성함.
        String accessToken = jwtUtil.generateAccessToken(existingUser);
        String refreshToken = jwtUtil.generateRefreshToken(existingUser);

        // Access Token을 데이터베이스에 저장함.
        userService.saveAccessToken(existingUser.getUsername(), accessToken);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);  // Access Token을 맵에 추가함.
        tokens.put("refreshToken", refreshToken);  // Refresh Token을 맵에 추가함.
        return ResponseEntity.ok(tokens);  // 토큰 정보를 반환함.
    }

    // 사용자 정보 업데이트 요청을 처리하는 메서드
    @PutMapping("/update")
    public ResponseEntity<?> update(@RequestBody User user) {
        // 사용자 정보를 업데이트함.
        User updatedUser = userService.update(user);  
        return ResponseEntity.ok(updatedUser);  // 업데이트된 사용자 정보를 반환함.
    }

    // 로그아웃 요청을 처리하는 메서드
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        // 로그아웃 로직 (클라이언트 측에서 토큰 삭제)
        // 필요시 서버 측에서 토큰을 무효화하는 로직 추가 가능
        return ResponseEntity.ok("Logged out successfully");  // 로그아웃 성공 메시지를 반환함.
    }

    // 토큰 갱신 요청을 처리하는 메서드
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> tokens) {
        // 클라이언트로부터 Refresh Token을 받음.
        String refreshToken = tokens.get("refreshToken");  
        // Refresh Token이 없거나 만료되었으면 400 Bad Request 응답을 반환함.
        if (refreshToken == null || jwtUtil.isTokenExpired(refreshToken)) {
            return ResponseEntity.badRequest().body("Invalid refresh token");  
        }
        // Refresh Token에서 사용자 이름을 추출함.
        String username = jwtUtil.extractUsername(refreshToken);  
        // 사용자 이름으로 사용자 정보를 찾음.
        User user = userService.findByUsername(username);  
        // 사용자가 없으면 400 Bad Request 응답을 반환함.
        if (user == null) {
            return ResponseEntity.badRequest().body("User not found");  
        }
        // 새로운 Access Token을 생성함.
        String newAccessToken = jwtUtil.generateAccessToken(user);  

        // 새로운 Access Token을 데이터베이스에 저장함.
        userService.saveAccessToken(user.getUsername(), newAccessToken);

        Map<String, String> newTokens = new HashMap<>();
        newTokens.put("accessToken", newAccessToken);  // 새로운 Access Token을 맵에 추가함.
        return ResponseEntity.ok(newTokens);  // 새로운 토큰 정보를 반환함.
    }
}

