package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//⭐
// http://localhost:8080/login 요청이 올 때 이 메서드가 동작을 함. => 이제 여기서 동작 안한다.⭐⭐
// ⭐그래서 PrincipalDetailsService <- 애를 때려주는(?) 필터를 하나 만들어야해
// 왜 하필 이 url? 스프링 시큐리티의 기본적인 로그인 요청 주소가 /login이라서!!
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByUsername()");
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity:"+userEntity);
        return new PrincipalDetails(userEntity);
    }
}
