package com.cos.jwt.controller;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {


    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }


    // 알맞는 토큰이 날라올 때만 컨트롤러를 진입하게 하고
    // 유효하지 않은 토큰일 경우 더 이상 필터를 못타게 하여 컨트롤러 진입 못하도록 구현하자
    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    //회원가입로직
    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    // user, manager, admin 권한만 접근 가능
    @GetMapping("/api/v1/user")
    public String user(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal = " + principal);
        return "user";
    }

    // manager, admin
    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    // only admin
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }


}
