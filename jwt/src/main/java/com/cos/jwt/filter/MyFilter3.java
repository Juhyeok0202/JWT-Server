package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰: cos 이걸 만들어줘야함.
        // 언제 만들어?
        // id,pw 정상적으로 들어와서 로그인이 완료 되면 토큰을 만들어주고 그걸 응답을 해준다.
        // 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 오겠죠?
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨.(RSA or HS256을 통해서)
        System.out.println("필터3");
//        if (req.getMethod().equals("POST")) {
//            System.out.println("POST요청됨");
//            String headerAuth = req.getHeader("Authorization");
//            System.out.println("headerAuth = " + headerAuth);
//
//            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
//            } else {
//                PrintWriter out = res.getWriter();
//                out.println("인증실패");
//            }
//        }
    }
}
