package com.example.springsecurity.config.jwt;

import com.example.springsecurity.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class TokenProvider {

    private final JwtProperties jwtProperties;

    public String generateToken(User user, Duration expiredAt) {
        Date now = new Date();
        return makeToken(new Date(now.getTime() + expiredAt.toMillis()), user);
    }

    //jjwt라이브러리를 사용하여 JWT를 생성 - JWT 토큰 생성 메서드
    private String makeToken(Date expiry, User user) {
        Date now = new Date();

        /**
         * Jwts
         * : JWT 라이브러리인 jjwt(Java JWT) 라이브러리의 일부 & JWT를 생성하기 위한 유틸리티 클래스
         * JSON Web Token을 생성하고 파싱하는데 사용
         */

        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE) //헤더
                .setIssuer(jwtProperties.getIssuer()) //발급자
                .setIssuedAt(now) //발급일시
                .setExpiration(expiry) //만료인시
                .setSubject(user.getEmail()) //주제
                .claim("id", user.getId()) //클레임 -- JWT내용을 설명하고 추가 정보를 제공
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey()) //jwt 서명 : 비밀값과 함께 해시값을 HS256방식으로 암호화
                .compact();
    }

    //JWT 토큰 유효성 검증 및 파싱
    public boolean validToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey()) // JWT의 서명을 검증하기 위해 사용할 서명키를 설정 --> 서명키는 사용된 비밀키와 일치
                    .parseClaimsJws(token);  //주어진 JWT를 파싱하고 서명 검증 -- 클레임 정보를 추출하여 서명 유효한지 확인

            return true;
        } catch (Exception e) { //복호화
            return false;
        }
    }


    //토큰 기반으로 인증 정보를 가져오는 메서드 -> Authentication 객체생성하여 시큐리티에서 사용자의 인증 및 권한 부여 관리하는데 이용
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        //ROLE_USER 권한을 가진 SimpleGrantedAuthority 객체(사용자의 권한을 나타내는 객체) 생성
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));

        //SimpleGrantedAuthority, claims의 정보를 사용하여 Authentication 객체 생성
        return new UsernamePasswordAuthenticationToken(new org.springframework.security.core.userdetails.User(claims.getSubject
                (), "", authorities), token, authorities);
    }

    //토큰 기반으로 유저 id를 가져오는 메서드
    public Long getUserId(String token) {
        Claims claims = getClaims(token);
        return claims.get("id", Long.class); //id클레임을 추출하여 Long 타입으로 변환
    }

    private Claims getClaims(String token) {
        return Jwts.parser() //클레임 조회
                .setSigningKey(jwtProperties.getSecretKey())
                .parseClaimsJws(token)
                .getBody();
    }
}
