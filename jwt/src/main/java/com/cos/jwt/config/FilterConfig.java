package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration //IoC 등록 => 메모리에 등록
public class FilterConfig {

    //⭐이 필터를 이용해서 jwt 토큰 처리를 해볼 예정

    //⭐굳이 SecurityConfig에서 시큐리티 필터체인에 걸 필요 X
    // 이렇게 따로 필터를 걸어두는게 난 더 좋음
    // 이 방식은 Security Filter Chain보다 먼저 실행될까? 나중에 실행될까? => 시큐리티 필터가 우선!
    // Security 필터가 다~~ 끝나야 다른게 시작됨.
    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*"); // 모든 요청에서 다 해라
        bean.setOrder(0); // 우선순위:0 - 낮은 번호가 필터중에서 가장 먼저 실행됨.
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(1); //Myfilter1 다음에 1번째인 filter2가 실행됨.
        return bean;
    }


}
