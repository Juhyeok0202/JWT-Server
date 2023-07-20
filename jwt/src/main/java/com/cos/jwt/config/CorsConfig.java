package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    // Spring 프레임워크가 들고 있는 "CorsFilter"를 import해야함
    @Bean
    public CorsFilter corsFilter() { //이렇게 설정만 하면 의미X 필터에 등록을 해주어야함. -> SecurityConfig
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때, json을 자바스크립트에서 처리할 수 있게 할지를 설정하는 것.
        config.addAllowedOrigin("*"); // 모든 ip에 응답을 허용하겠다.
        config.addAllowedHeader("*"); // 모든 header에 응답을 허용하겠다.
        config.addAllowedMethod("*"); // 모든 post,get,put,delete,patch 요청을 허용하겠다.

        //  /api/** 을 타고온 모든 주소는 config 설정을 따를 것
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);

    }
}
