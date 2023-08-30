package com.example.springsecurity.config;

import jakarta.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//         http.csrf().disable();
//    http.headers().frameOptions().disable();
    http.authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/users/**").permitAll()
          .requestMatchers(PathRequest.toH2Console()).permitAll()
    );


//        http
////                .csrf().disable().cors().disable()
//                .authorizeHttpRequests(request -> request
////                        .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
//                        .requestMatchers("/").permitAll()
//                        .requestMatchers("/member/**").authenticated()
//                        .requestMatchers("/admin/**").hasRole("ADMIN")
//                        .requestMatchers("/manager/**").hasRole("MANAGER")
//                        .anyRequest().authenticated()
//                )
//                .formLogin(login -> login
//                        .loginPage("/login")    //로그인 페이지 설정
//                        .loginProcessingUrl("/login")    //로그인 처리 URL 설정
//                        .usernameParameter("username")    // [C] submit할 아이디
//                        .passwordParameter("password")    // [D] submit할 비밀번호
//                        .defaultSuccessUrl("/loginSuccess", true)  //로그인 성공 후 이동할 페이지
//                        .permitAll()
//                )
//                .logout(withDefaults());

        return http.build();
    }
}