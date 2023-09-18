package com.example.springsecurity.config;

import com.example.springsecurity.config.jwt.TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;

    private final static String HEADER_AUTHORIZATION = "Authorization";
    private final static String TOKEN_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)  throws ServletException, IOException {

        //HTTP 요청의 헤더에서 "Authorization" 헤더 값을 가져옴
        String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);
        //위의 헤더값에서 실제 엑세스 토큰을 추출
        String token = getAccessToken(authorizationHeader);

        //만약 토큰이 유효하다면, JWT 토큰을 사용하여 사용자 인증 정보를 추출하여 사용자의 보안 컨텍스트 설정
        //이후 요청에서 사용자의 신원을 파악할 수 있다.
        if (tokenProvider.validToken(token)) {
            Authentication authentication = tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        //현재 필터의 작업이 완료되면 다음 필터로 요청과 응답을 전달
        filterChain.doFilter(request, response);
    }

    private String getAccessToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            return authorizationHeader.substring(TOKEN_PREFIX.length());
        }

        return null;
    }
}

