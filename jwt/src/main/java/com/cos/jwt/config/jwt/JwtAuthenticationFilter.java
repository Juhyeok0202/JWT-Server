package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// 이 필터는 /login 요청해서 username,password 전송하면(post로)
// UsernamePasswordAuthenticationFilter가 동작을 한다.

// /login이라고 요청이 오면 UsernamePasswordAuthenticationFilter가 낚아채서
// attemptAuthentication 메서드가 자동으로 실행 됨.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    // 현재 SecurityConfig에서 formLogin 비활성화 시켜서 작동안하는 상태임
    // 어떻게 다시 작동을 시키냐면?
    // JwtAuthenticationFilter를 다시 SecurityConfig에 등록해주어야 함.

    // 로그인을 진행하는 필터기 때문에 AuthenticationManager(매니저)를 통해서 로그인 진행함.
    // 그래서 SecurityConfig에서 이 필터 등록할 때 AuthenticationManager을 같이 던져줘야함.
    // AuthenticationManager는 WebSecurityConfigurerAdapter가 가지고 있음.

    private final AuthenticationManager authenticationManager;
    //이제 authenticationManager 을 통해서 로그인을 시도하면 돼

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");
        // 1. username,password 받아서
        try {
            // 이 request.getInputStream() 라는 Byte 안에 username,pw가 담겨있다.
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }

            //⭐⭐이 클래스는 JSON 데이터를 파싱해줌
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("JSON데이터 파싱히힐힝리힐힐히"+user); // 💡왜 id=null??

            // 로그인 시도 하려면 Token 직접 만들어야함.
            // 원래 폼로그인에서 해주는데, 우리가 직접 가입해야되기 때문에
            // 이 토큰으로 로그인 시도 할 거임
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이게 실행 될 때,
            // PrincipalDetailsService의 loadUserByUsername()함수가 실행됨
            // ⬆️ loadUserByUsername는 토큰의 username 만 받음
            // password는 !!! spring 안에서 DB에서 처리 해줌.(내부적으로 궁그해하지마)
            // [Flow:]authenticationManager에 토큰을 넣어 던지면 ➡️ 인증을 해줌️➡️ 인증이 되면!!! => authentication이 받겠죠?
            // 이 authentication에는 내 로그인 한 정보가 담김.
            //  authentication이 만들어 졌다는 것 => 로그인이 정상적으로 되었다는 것
            // DB에 있는 username과 password가 일치한다.(인증 끝)
            Authentication authentication
                    = authenticationManager.authenticate(authenticationToken);

            //(test)
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨: "+principalDetails.getUser().getUsername()); // 값이 있다 => 로그인 정상적으로 되었다는 뜻.
            // authentication 객체가 session영역에 저장을 해야하고 그 방법이 return 해주면 됨.
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임.
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session에 넣어 줌.

            // (넣기 직전에) JWT토큰을 만들어줌.
            return authentication; //리턴하면  authenticationr 객체가 session영역에 저장됨.

        } catch (IOException e) {
            System.out.println("예외발생");
            e.printStackTrace();
        }
        // 2. 정상인지 로그인 시도를 해보는 거에요. ⭐authenticationManager로 로그인 시도를 하면!!
        // PrincipalDetailsService가 호출 loadUserByUsername이 자동으로 실행됨.

        // 3. (2)가 리턴이 되면 PrincipalDetails 를 세션에 담고(권한 관리 위해)
            //굳이 PrincipalDetails를 세션에 담는 이유는
            //이걸 세션에 담지 않으면, 권한 관리가 안됨 antMatchers같은 것들
            // 세션에 값이 있어야 시큐리티가 권한 관리를 해줌!!

        // 4. JWT토큰을 만들어서 응답해주면 됨.
         return null;
    }


    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면, successfulAuthentication 함수가 실행.
    // (여기서)JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain
            , Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임.");

        //principalDetails을 이용해서 JWT를 만들건데, 라이브러리를 활용할 것임.
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA방식(X) Hash암호방식
        String jwtToken = JWT.create()
                .withSubject(JwtProperties.SECRET) // 토큰 이름. 큰 의미 X
                //System.currentTimeMillis(): 1/1000 초
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) // 만료시간:10분 -> 짧게 해야 탈취 당해도 위험 부담 적음
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUsername())
                .sign(Algorithm.HMAC256(JwtProperties.SECRET)); //내 서버만 아는 고유한 값을 secret으로

        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX +jwtToken);


    }
}
