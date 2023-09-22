package com.example.springsecurity.config.oauth;

import com.example.springsecurity.config.jwt.TokenProvider;
import com.example.springsecurity.domain.RefreshToken;
import com.example.springsecurity.domain.User;
import com.example.springsecurity.repository.RefreshTokenRepository;
import com.example.springsecurity.service.UserService;
import com.example.springsecurity.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Duration;

@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(14);
    public static final Duration ACCESS_TOKEN_DURATION = Duration.ofDays(1);
    public static final String REDIRECT_PATH = "/articles";

    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        // authentication.getPrincipal() : Authentication에서 제공하는 메서드로 현재 인증된 사용자 객체를 불러오는 메서드
        // OAuth2User : 시큐리티에서 OAuth 2.0 인증 프로세스와 관련된 사용자 정보를 나타내는데 사용되는 인터페이스
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        User user = userService.findByEmail((String) oAuth2User.getAttributes().get("email"));

        //리프레시 토큰 생성 -> 저장 -> 쿠키에 저장
        String refreshToken = tokenProvider.generateToken(user, REFRESH_TOKEN_DURATION);
        saveRefreshToken(user.getId(), refreshToken);
        addRefreshTokenToCookie(request, response, refreshToken);

        //액세스 토큰 생성 -> 패스에 액세스 토큰 추가
        String accessToken = tokenProvider.generateToken(user, ACCESS_TOKEN_DURATION);
        String targetUrl = getTargetUrl(accessToken);

        //인증 관련 설정값, 쿠키 제거 : 인증 프로세스를 진행하면서 세션과 쿠키에 임시로 저장해둔 인증 관련 데이터를 제거
        //임시 데이터 ex) 로그인 페이지로 이동하고 인증을 시도할 떄, 사용자의 인증 요청 정보나 상태를 임시로 저장
        clearAuthenticationAttributes(request, response);

        //리다이렉트
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    //생성된 리프레시 토큰을 전달받아 데이터베이스에 전달
    private void saveRefreshToken(Long userId, String newRefreshToken) {
        RefreshToken refreshToken = refreshTokenRepository.findByUserId(userId)
                .map(entity -> entity.update(newRefreshToken)) //findByUserId(userId) 결과 존재시 기존 리프레시 토큰을 업데이트 한 후 업데이터된 RefreshToken 객체를 반환
                .orElse(new RefreshToken(userId, newRefreshToken)); //findByUserId(userId) 메서드 결과가 비어있거나 존재하지 않을 때 새로운 객체 생성

        refreshTokenRepository.save(refreshToken);
    }

    //기존 리프레시 토큰 쿠키 삭제 후 새로운 리프레시 토큰 추가
    private void addRefreshTokenToCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        int cookieMaxAge = (int) REFRESH_TOKEN_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN_COOKIE_NAME);
        CookieUtil.addCookie(response, REFRESH_TOKEN_COOKIE_NAME, refreshToken, cookieMaxAge);
    }

    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);  // OAuth2LoginAuthenticationFilter의 메서드로써 사용자 인증과 관련된 일부 속성 제거
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    //액세스 토큰을 패스에 추가 : REDIRECT_PATH라는 기본 경로에 token 매개변수와 해당 값을 추가하여 URI 문자열 생성
    //UriComponentsBuilder : Spring FrameWork에서 제공하는 클래스로, URI를 구성하고 조작하는데 이용
    //fromUriString(REDIRECT_PATH) : REDIRECT_PATH 문자열로부터 UriComponentsBuilder 객체를 생성
    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_PATH)
                .queryParam("token", token)
                .build() //UriComponentsBuilder 객체를 사용하여 URI 문자열을 최종적으로 생성하고 uri 객체를 변환
                .toUriString(); //uri객체를 최종적인 URI 문자열을 반환
    }
}
