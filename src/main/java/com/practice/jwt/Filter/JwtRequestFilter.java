package com.practice.jwt.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
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

    @Lazy
    @Autowired
    private JwtUtil jwtUtil;

    @Lazy
    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // Authorization 헤더에서 JWT 토큰을 가져옴
        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String accessToken = null;

        // Authorization 헤더가 존재하고 "Bearer "로 시작하는 경우
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            accessToken = authorizationHeader.substring(7); // "Bearer " 이후의 부분을 추출하여 accessToken으로 사용
            System.out.println("access token : "+accessToken);
            try {
                username = jwtUtil.extractUsername(accessToken); // JWT에서 사용자 이름 추출
                System.out.println("username : "+username);
            } catch (ExpiredJwtException e) {
                // Access 토큰이 만료된 경우
            	System.out.println("access token 만료됨 ");
                final String refreshToken = request.getHeader("Refresh-Token"); // 요청 헤더에서 "Refresh-Token" 헤더를 가져옴
                System.out.println("refresh token : "+refreshToken);
                if (refreshToken != null) {
                    try {
                        username = jwtUtil.extractUsername(refreshToken); // Refresh 토큰에서 사용자 이름 추출
                        User user = userService.findByUsername(username); // UserService를 통해 사용자 정보 조회
                        if (user != null && !jwtUtil.isTokenExpired(refreshToken)) {
                            // Refresh 토큰이 유효한 경우 새로운 Access 토큰 생성
                            String newAccessToken = jwtUtil.generateAccessToken(user);
                            response.setHeader("Authorization", "Bearer " + newAccessToken); // 새로운 Access 토큰을 응답 헤더에 설정
                            username = jwtUtil.extractUsername(newAccessToken); // 새로운 Access 토큰에서 사용자 이름 추출
                        } else {
                            // Refresh 토큰이 유효하지 않은 경우
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            response.getWriter().write("{\"error\": \"Invalid refresh token\"}");
                            return;
                        }
                    } catch (ExpiredJwtException ex) {
                        // Refresh 토큰이 만료된 경우
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("{\"error\": \"Refresh token expired\"}");
                        return;
                    } catch (Exception ex) {
                        // Refresh 토큰이 유효하지 않은 경우
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("{\"error\": \"Invalid refresh token\"}");
                        return;
                    }
                } else {
                    // Refresh 토큰이 없는 경우
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\": \"Access token expired\"}");
                    return;
                }
            } catch (Exception e) {
                // Access 토큰이 유효하지 않은 경우
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Invalid access token\"}");
                return;
            }
        }

        // 사용자 이름이 존재하는 경우
        if (username != null) {
        	System.out.println("사용자 이름 존재. 사용자 이름 : "+username);
            User user = userService.findByUsername(username);  // 사용자 정보 조회
            if (jwtUtil.validateToken(accessToken, user)) {
                request.setAttribute("username", username);  // 요청에 사용자 이름 속성 설정
            }
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Invalid token\"}");
            return;
        }

        chain.doFilter(request, response);  // 필터 체인 계속 진행
    }
}


