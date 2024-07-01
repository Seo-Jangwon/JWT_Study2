package com.practice.jwt.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.practice.jwt.entity.User;
import com.practice.jwt.service.UserService;
import com.practice.jwt.util.JwtUtil;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;  // UserService를 자동으로 주입받음.

    @Autowired
    private JwtUtil jwtUtil;  // JwtUtil을 자동으로 주입받음.

    // 회원가입 요청을 처리하는 메서드
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody User user) {
        if (userService.findByUsername(user.getUsername()) != null) {  // 사용자 이름이 이미 존재하는지 확인함.
            return ResponseEntity.badRequest().body("Username already exists");  // 사용자 이름이 존재하면 400 Bad Request 응답을 반환함.
        }
        User savedUser = userService.save(user);  // 사용자 정보를 저장함.
        return ResponseEntity.ok(savedUser);  // 저장된 사용자 정보를 반환함.
    }

    // 로그인 요청을 처리하는 메서드
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        User existingUser = userService.findByUsername(user.getUsername());  // 사용자 이름으로 기존 사용자 정보를 찾음.
        if (existingUser == null || !new BCryptPasswordEncoder().matches(user.getPassword(), existingUser.getPassword())) {
            return ResponseEntity.badRequest().body("Invalid username or password");  // 사용자 정보가 없거나 비밀번호가 일치하지 않으면 400 Bad Request 응답을 반환함.
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
        User updatedUser = userService.update(user);  // 사용자 정보를 업데이트함.
        return ResponseEntity.ok(updatedUser);  // 업데이트된 사용자 정보를 반환함.
    }

    // 로그아웃 요청을 처리하는 메서드
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        // 로그아웃 로직 (클라이언트 측에서 토큰 삭제)
        return ResponseEntity.ok("Logged out successfully");  // 로그아웃 성공 메시지를 반환함.
    }

    // 토큰 갱신 요청을 처리하는 메서드
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> tokens) {
        String refreshToken = tokens.get("refreshToken");  // 클라이언트로부터 Refresh Token을 받음.
        if (refreshToken == null || jwtUtil.isTokenExpired(refreshToken)) {
            return ResponseEntity.badRequest().body("Invalid refresh token");  // Refresh Token이 없거나 만료되었으면 400 Bad Request 응답을 반환함.
        }
        String username = jwtUtil.extractUsername(refreshToken);  // Refresh Token에서 사용자 이름을 추출함.
        User user = userService.findByUsername(username);  // 사용자 이름으로 사용자 정보를 찾음.
        if (user == null) {
            return ResponseEntity.badRequest().body("User not found");  // 사용자가 없으면 400 Bad Request 응답을 반환함.
        }
        String newAccessToken = jwtUtil.generateAccessToken(user);  // 새로운 Access Token을 생성함.

        // 새로운 Access Token을 데이터베이스에 저장함.
        userService.saveAccessToken(user.getUsername(), newAccessToken);

        Map<String, String> newTokens = new HashMap<>();
        newTokens.put("accessToken", newAccessToken);  // 새로운 Access Token을 맵에 추가함.
        return ResponseEntity.ok(newTokens);  // 새로운 토큰 정보를 반환함.
    }
}

