package com.practice.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.practice.jwt.Exception.UserNotFoundException;
import com.practice.jwt.Repository.UserRepository;
import com.practice.jwt.entity.User;


@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder  passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder  = passwordEncoder;
        System.out.println("UserService 생성.");
    }

    // 사용자 정보를 저장하는 메서드
    public User save(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));  // 사용자의 비밀번호를 암호화함.
        return userRepository.save(user);  // 암호화된 비밀번호를 포함한 사용자 정보를 저장하고 반환함.
    }

    // 사용자 이름으로 사용자를 찾는 메서드
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("사용자를 찾을 수 없습니다: " + username));  // 사용자 이름으로 사용자 정보를 찾고 반환함.
    }
    
    // 사용자 정보를 업데이트하는 메서드
    public User update(User user) {
        User existingUser = userRepository.findById(user.getId())
                .orElseThrow(() -> new UserNotFoundException("사용자를 찾을 수 없습니다: " + user.getId()));  // 사용자 ID로 기존 사용자 정보를 찾음. 없으면 예외를 발생시킴.
        
        if (!passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {  // 입력된 비밀번호가 기존 비밀번호와 일치하지 않는 경우
            user.setPassword(passwordEncoder.encode(user.getPassword()));  // 새로운 비밀번호를 암호화함.
        } else {
            user.setPassword(existingUser.getPassword());  // 기존 비밀번호를 유지함.
        }
        
        return userRepository.save(user);  // 업데이트된 사용자 정보를 저장하고 반환함.
    }
    
    /**
     * 주어진 사용자 이름을 기반으로 사용자를 찾고
     * 해당 사용자에게 액세스 토큰을 저장
     * 
     * @param username   사용자의 이름
     * @param accessToken 저장할 액세스 토큰
     * @throws RuntimeException 사용자가 존재하지 않는 경우 예외를 발생시킴
     */
    @Transactional // 메서드 실행 중 예외가 발생하면 자동으로 롤백
    public void saveAccessToken(String username, String accessToken) {
        // 주어진 사용자 이름으로 사용자를 찾음
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // 사용자의 액세스 토큰을 설정
        user.setAccessToken(accessToken);
        // 변경된 사용자를 데이터베이스에 저장
        userRepository.save(user);
    }
}


