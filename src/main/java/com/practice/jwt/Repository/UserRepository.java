package com.practice.jwt.Repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.practice.jwt.entity.User;

/**
 * UserRepository는 JpaRepository를 확장하여 User 엔티티에 대한 데이터 접근을 담당함
 * JpaRepository는 기본적인 CRUD(생성, 읽기, 업데이트, 삭제) 메서드를 제공함
 */
public interface UserRepository extends JpaRepository<User, Long> {
    
    /**
     * 사용자 이름(username)으로 User 엔티티를 찾는 메서드
     * @param username 찾고자 하는 사용자의 이름
     * @return 주어진 사용자 이름에 해당하는 User 객체, 없으면 null
     */
	 Optional<User> findByUsername(String username);
}