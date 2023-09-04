package com.example.springsecurity.repository;

import com.example.springsecurity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * email로 사용자 정보를 가져온다 -> 스프링 시큐리티가 이메일을 전달받아야한다.
 * JPA 메서드 규칙에 맞춰 findByEmail()
 */
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}

