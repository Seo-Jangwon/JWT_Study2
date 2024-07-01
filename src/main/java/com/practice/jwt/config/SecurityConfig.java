package com.practice.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.practice.jwt.Filter.JwtRequestFilter;

@Configuration // 이 클래스가 Spring 설정 클래스임을 나타냄.
@EnableWebSecurity // Spring Security를 활성화함.
public class SecurityConfig {

	@Lazy
    @Autowired
    private JwtRequestFilter jwtRequestFilter;
	
    /**
     * SecurityFilterChain 빈을 생성.
     * 이 메서드는 HttpSecurity를 사용하여 보안 구성을 정의.
     *
     * @param http HttpSecurity 객체
     * @return SecurityFilterChain 객체
     * @throws Exception 예외가 발생할 수 있음.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // CSRF 보호를 비활성화.
            .authorizeHttpRequests(authorize -> authorize
                //.requestMatchers("/user/signup", "/user/login").permitAll() // 제거 의도
                .anyRequest().authenticated() // 나머지 모든 요청은 인증이 필요함.
            )
            .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
            .httpBasic().and()
            .formLogin();

        return http.build();
    }
    
    /**
     * PasswordEncoder 빈을 생성.
     * 이 메서드는 BCryptPasswordEncoder를 사용하여 비밀번호를 암호화.
     *
     * @return BCryptPasswordEncoder 객체
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        System.out.println("BCryptPasswordEncoder Bean 생성."); // 빈 생성 시 로그 출력
        return new BCryptPasswordEncoder(); // BCryptPasswordEncoder 객체를 반환.
    }
}
