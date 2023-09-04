package com.example.springsecurity.config;

import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    BoardUserDetailsService boardUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//         http.csrf().disable();
//    http.headers().frameOptions().disable();
        //3.1.2 ~ 3.0.10
//        http.authorizeHttpRequests(authorize -> authorize
//                .requestMatchers(new AntPathRequestMatcher("/")).permitAll()
//                .requestMatchers(new AntPathRequestMatcher("/member/**")).authenticated()
//                .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")
//                .anyRequest().authenticated()
//        );


        //3.0.2
        http
                .csrf().disable().cors().disable()
                .authorizeHttpRequests(request -> request
                        .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/member/**").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/manager/**").hasRole("MANAGER")
                        .anyRequest().authenticated()
                )
                .formLogin(login -> login
                        .loginPage("/login")    //로그인 페이지 설정
                        .loginProcessingUrl("/login")    //로그인 처리 URL 설정
                        .defaultSuccessUrl("/loginSuccess", true)  //로그인 성공 후 이동할 페이지
//                        .successHandler(authSuccessHandler)
//                        .failureHandler(authFailureHandler)
                        .permitAll()
                )
                .userDetailsService(boardUserDetailsService)
                .logout(withDefaults());

        return http.build();
    }

    @Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}