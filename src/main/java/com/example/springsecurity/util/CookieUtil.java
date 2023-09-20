package com.example.springsecurity.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;

import java.util.Base64;

public class CookieUtil {

    //요청값(이름, 값, 만료기간)을 바탕으로 쿠키 추가
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/"); //쿠키의 유효한 경로 설정
        cookie.setMaxAge(maxAge); //쿠키 수명

        response.addCookie(cookie); //HttpServletResponse 자체 메서드 : 쿠키를 응답에 추가
    }

    //쿠키의 이름을 입력받아 쿠키 삭제
    //실제 삭제하는 방법이 없기때문에 파라미터로 넘어온 키의 쿠키를 빈 값으로 바꾸고 만료 시간을 0으로 설정해 쿠키가 재생성 되자마자 만료 처리
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies(); //클라이언트로부터 받은 모든 쿠키를 가져옴

        if (cookies == null) {
            return;
        }

        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) { //삭제하려는 쿠키 이름과 순회 중인 쿠키 이름(name) 비교
                cookie.setValue(""); //쿠키의 값을 빈 문자열("")로 설정
                cookie.setPath("/"); //쿠키가 모든 경로에서 유효
                cookie.setMaxAge(0); //즉각 만료
                response.addCookie(cookie);
            }
        }
    }

    //객체를 직렬화해 쿠키의 값으로 변환 ( 직렬화 : 받은 객체를 문자열로 반환) : URL에서 안전하게 전송하거나 저장할 수 있는 문자열로 반환
    public static String serialize(Object obj) {
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(obj));
    }

    //쿠키를 역직렬화해 객체로 변환
    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        return cls.cast(
                SerializationUtils.deserialize(
                        Base64.getUrlDecoder().decode(cookie.getValue())
                )
        );
    }
}

