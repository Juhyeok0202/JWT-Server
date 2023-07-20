package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration //IoC할 수 있게 만들어 주고
@EnableWebSecurity
@RequiredArgsConstructor //DI를 위한
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    /*
    form로그인 X
    기본적인 http 로그인 방식 아예 X
    세션 사용 X 무상태성 서버로 만듬
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
        이렇게 되면 시큐리티를 쓰고 있는데,
        세션이 안되니까
        모든 페이지에 접근이 가능해짐.
         */

        //굳이 시큐리티 필터에 걸 필요는 없고 따로 만들어도 됨.( 만든 필터보다 시큐리티 필터에 등록한게 먼저 실행됨!!)
        //아래의 코드는 Myfiler3가 Security가 동작하기 전에 실행이 됨. 동작 전에 걸러내야함
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // 💡잘 이해가 안감.

        http.csrf().disable();
        //세션을 사용하지 않겠다는 말. StateLess Server로 만들겠다는 의미의 한줄 코드
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter) // 이 필터를 타야 모든 요청. 내 서버는 CORS정책에서 벗어날 수 있음. 다 허용이 됨.
                .formLogin().disable() // jwt서버니까 id,password를 form로그인 안해도 됨(⭐여기까진 사실상 고정)
                .httpBasic().disable() //
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // 인증 필터: 꼭 넘겨야하는 param: AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)) // 인가 필터
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

    }
}
