package com.example.springsecurity.service;

import com.example.springsecurity.config.jwt.TokenProvider;
import com.example.springsecurity.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    public String createNewAccessToken(String refreshToken) {
        // 토큰 유효성 검사에 실패하면 예외 발생
        if(!tokenProvider.validToken(refreshToken)) {
            throw new IllegalArgumentException("Unexpected token");
        }

        //유효한 리프레시 토큰을 기반으로 해당 토큰에 연결된 사용자 ID를 찾습니다.
        Long userId = refreshTokenService.findByRefreshToken(refreshToken).getUserId();
        User user = userService.findById(userId);

        //검색한 사용자 정보를 사용해서 새로운 엑세스 토큰 생성
        return tokenProvider.generateToken(user, Duration.ofHours(2));
    }
}

