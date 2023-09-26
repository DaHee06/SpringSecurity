package com.example.springsecurity.config.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 *  JWT (JSON Web Token) 관련 설정 정보를 저장하고 관리하는 클래스
 * @ConfigurationProperties : 설정 파일(application.properties 또는 application.yml)에서 가져온 JWT 관련 속성 값을 저장
 *
 */
@Setter
@Getter
@Component
@ConfigurationProperties("jwt")
public class JwtProperties {

    private String issuer;
    private String secretKey;
}

