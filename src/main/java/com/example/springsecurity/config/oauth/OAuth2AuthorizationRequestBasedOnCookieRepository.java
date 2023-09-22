package com.example.springsecurity.config.oauth;

import com.example.springsecurity.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.util.WebUtils;

/**
 * OAuth2에 필요한 정보를 세션이 아닌 쿠키에 저장해서 쓸 수 있도록 인증 요청과 관련된 상태를 저장할 저장소를 구현
 * AuthorizationRequestRepository
 *  - 권한 인증 흐름에서 클라이언트의 요청을 유지하는데 사용
 *  - Spring Security에서 OAuth 2.0 및 openID Connect와 같은 인증 프로토콜에 사용되는 인증 요청 데이터를 저장하고 관리하는 인터페이스
 *  - 인터페이스 구현시 인증 요청을 세션, 쿠키, 데이터베이스 또는 다른 사용자 지정 저장소에 저장
 */
public class OAuth2AuthorizationRequestBasedOnCookieRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public final static String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    private final static int COOKIE_EXPIRE_SECONDS = 18000;

    //저장된 OAuth2AuthorizationRequest를 삭제, 인증 프로세스가 완료되고 더 이상 요청이 필요하지 않을 때
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        return this.loadAuthorizationRequest(request);
    }

    //저장된 OAuth2AuthorizationRequest를 요청해서 검색, 사용자가 인증 후 리디렉션되었을 때, 이 메서드를 사용하여 저장된 요청을 검색하여 인증 프로세스를 계속
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        return CookieUtil.deserialize(cookie, OAuth2AuthorizationRequest.class);
    }

    //OAuth2AuthorizationRequest 객체를 저장, 사용자의 인증 요청을 저장할 수 있으며, 일반적으로 사용자가 로그인 페이지로 리디렉션 되기 전에 호출
    //authorizationRequest : 저장할 OAuth2 인증 요청 객체. 클라이언트ID, 리다이렉션 URI, 스코프 등의 중요 정보가 존재
    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeAuthorizationRequestCookies(request, response);
            return;
        }

        CookieUtil.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtil.serialize(authorizationRequest), COOKIE_EXPIRE_SECONDS);
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        CookieUtil.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
    }
}
