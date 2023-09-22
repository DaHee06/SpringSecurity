package com.example.springsecurity.service;

import com.example.springsecurity.domain.User;
import com.example.springsecurity.dto.AddUserRequest;
import com.example.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
//    private final BCryptPasswordEncoder bCryptPasswordEncoder;
//
//    public Long save(AddUserRequest dto) {
//        return userRepository.save(User.builder()
//                .email(dto.getEmail())
//                //패스워드 암호화
//                .password(bCryptPasswordEncoder.encode(dto.getPassword()))
//                .build()).getId();
//    }

    //BCryptPasswordEncoder 생성자를 사용해 직접 생성해서 패스워드를 암호화하게 함
    public Long save(AddUserRequest dto) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        return userRepository.save(User.builder()
                .email(dto.getEmail())
                .password(encoder.encode(dto.getPassword()))
                .build()).getId();
    }

    public User findById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unexpected user"));
    }

    //OAuth 인증 과정 중 추가
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Unexpected user"));
    }
}
