package com.example.springsecurity.service;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public User loadUserByUsername(String email) {
        return userRepository.findByEmail(email)
                 .orElseThrow(() -> new IllegalArgumentException((email)));
    }

    /**
     *  Java 8 이후에 도입된 기능으로, Java의 스트림(Stream) 및 옵셔널(Optional) API
     *  옵셔널(Optional) 객체에서 값이 존재하지 않을 경우 예외를 던지는 데 사용
     *
     *  UserDetailsService 인터페이스 구현시 loadUserByUsername 필수 구현
     */
}
