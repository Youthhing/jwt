package com.youth.jwt.config.auth;

import com.youth.jwt.model.User;
import com.youth.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

//http://localhost:8080/login요청이 올때 동작함
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    public UserDetails loadUserByUsername(String username){
        System.out.println("PrincipalDetailsService의 login 요청");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
