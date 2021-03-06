package com.cos.security1.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessingUrl("/login") 설정하면
// "/login" 요청이 왔을 때
// 스프링은 자동으로 IOC 컨테이너에서 UserDetailsService 타입으로 의존 주입되어 있는 객체를 찾는다.
// 그리고 loadUserByUsername() 메서드를 실행한다.
@Service
public class PrincipleDetailsService implements UserDetailsService {


    @Autowired
    private UserRepository userRepository;
    
    //1. return되는 UserDetails 값은 Authentication 객체 안에 들어가며, 그 객체는 시큐리티 세션 안으로 들어간다.
    //2. 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null) {
            return null;
        }
        return new PrincipalDetails(user);
    }
}
