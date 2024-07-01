package com.practice.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.practice.jwt.Filter.JwtRequestFilter;
import com.practice.jwt.service.UserService;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

// 이 클래스가 Spring의 구성 클래스임을 나타냄
@Configuration
public class FilterConfig {

    // JWT 요청 필터를 등록하는 메서드
    // @Bean 어노테이션을 사용하여 이 메서드가 반환하는 객체를 Spring 빈으로 등록
    @Bean
    public FilterRegistrationBean<JwtRequestFilter> jwtFilter(JwtRequestFilter filter) {
        // FilterRegistrationBean 객체 생성
        // 이 객체는 특정 필터를 등록하고 필터의 동작을 구성하는 데 사용됨
        FilterRegistrationBean<JwtRequestFilter> registrationBean = new FilterRegistrationBean<>();
        
        // 등록할 필터를 설정
        // 여기서는 JwtRequestFilter를 필터로 설정
        registrationBean.setFilter(filter);
        
        // 필터가 적용될 URL 패턴을 설정
        // "/api/*" 패턴의 URL에 대해 필터가 적용됨
        registrationBean.addUrlPatterns("/api/*");
        
        // 설정이 완료된 FilterRegistrationBean 객체를 반환
        // 이 객체는 Spring 컨테이너에 의해 관리되며 필터 체인에 추가됨
        return registrationBean;
    }
    
}
