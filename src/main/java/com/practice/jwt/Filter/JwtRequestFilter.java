package com.practice.jwt.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.practice.jwt.entity.User;
import com.practice.jwt.service.UserService;
import com.practice.jwt.util.JwtUtil;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;


@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String accessToken = null;
        
/*
 *1. 클라이언트 요청에서 Authorization 헤더를 확인하여 JWT 토큰을 추출
 *2. JWT 토큰에서 사용자 이름(username)을 추출하려고 시도함.
 *3. 사용자 이름을 성공적으로 추출했다면(username 변수가 null이 아닌 경우), 이후의 인증 과정을 진행
 * */        

        // Authorization 헤더에서 Access Token 추출
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7);
            try {
                // Access Token에서 사용자 이름 추출
                username = jwtUtil.extractUsername(accessToken);
            } catch (ExpiredJwtException e) {
                // Access Token이 만료된 경우
                String refreshToken = request.getHeader("Refresh-Token");
                if (refreshToken != null) {
                    try {
                        // Refresh Token에서 사용자 이름 추출
                        username = jwtUtil.extractUsername(refreshToken);
                        User user = userService.findByUsername(username);
                        if (user != null && !jwtUtil.isTokenExpired(refreshToken)) {
                            // 유효한 Refresh Token을 사용하여 새로운 Access Token 생성
                            String newAccessToken = jwtUtil.generateAccessToken(user);
                            response.setHeader("Authorization", "Bearer " + newAccessToken);
                            userService.saveAccessToken(user.getUsername(), newAccessToken);
                            
                            // 새로운 Access Token을 사용해서 사용자 이름 추출
                            username = jwtUtil.extractUsername(newAccessToken);
                        } else {
                            // Refresh Token이 유효하지 않은 경우
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("Invalid refresh token");
                            return;
                        }
                    } catch (ExpiredJwtException ex) {
                        // Refresh Token도 만료된 경우
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Refresh token expired");
                        return;
                    }
                } else {
                    // Refresh Token이 없는 경우
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Access token expired");
                    return;
                }
            }
        }

        // 사용자 이름이 있는 경우 (JWT 토큰에서 사용자 이름을 추출하는 데 성공)
        if (username != null) {
            User user = userService.findByUsername(username);
            // Access Token이 유효한 경우
            if (jwtUtil.validateToken(accessToken, user)) {
                // request에 사용자 정보를 설정하거나 기타 필요한 작업을 수행할 수 있음.
                request.setAttribute("username", username);
            }
        }

        // 필터 체인 계속 진행
        chain.doFilter(request, response);
    }
}


