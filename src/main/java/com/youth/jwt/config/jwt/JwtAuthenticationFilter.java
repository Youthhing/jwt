package com.youth.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.youth.jwt.config.auth.PrincipalDetails;
import com.youth.jwt.model.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
//login이라고 요청했을때  username, pw 전송하면 필터가 동작함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    /**
     * 1. username, password 받아서 2. 정상적인 로그인 시도 -> AuthenticationManager가 이를 받음 -> PrincipalDetailsService가 호출되어
     * loadByUsername 실행 3. PrincipalDetails를 세션에 담고(권한 리스트 때문에!!!) 4. Jwt 토큰 만들어서 응답
     */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("Jwt 로그인 시도");
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    user.getUsername(), user.getPassword());//id pw 인증
            //principalDetailsService의 loadByUsername이 실행됨
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principal.getUser().getUsername());
            System.out.println("================");
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("================");
        return null;
    }

    //인증이 정상적으로 되었다면! JWT 만들어서 사용자에게 전달
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        System.out.println("인증이 완료되었다는 뜻임");

        PrincipalDetails principal = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject(principal.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principal.getUser().getId())
                .withClaim("username", principal.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
        response.addHeader("accessToken", jwtToken);

    }
}
