package com.youth.jwt.filter;


import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        //ID, PW가 들어와서 정상적으로 로그인하면 토큰을 만들고 그것을 응답함
        //요청마다  header에 Authorization에 value값을 토큰을 가지고 있지?
        //그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨.
        if ("POST".equals(req.getMethod())){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            if ("youth".equals(headerAuth)){
                chain.doFilter(req,res);
            }else {
                PrintWriter writer = res.getWriter();
                writer.println("인증안됨");
            }
        }
    }
}
