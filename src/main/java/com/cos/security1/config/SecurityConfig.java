package com.cos.security1.config;

import com.cos.security1.auth.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
/*
google 로그인
1.코드 받기(인증)
2.엑세스 토큰 받기(정보 접근 권한 생김)
//구글 로그인 완료시 코드가 아닌 userRequest(엑세스 토큰 + 사용자 프로필 정보)를 받게 됨
//이를 이용하여 후처리
3.사용자 프로필 정보 가져오기 
4.정보를 토대로 회원가입 자동 진행 or
추가적인 정보가 필요하면 추가적인 회원 가입 창을 제공해야 함
*/
@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig 클래스)를 스프링 필터 체인에 등록하고 관리 시작
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    /*
    * .antMatchers()를 통해 로그인이 필요한 url을 정의
    * .formLogin()을 통해 로그인 페이지와 로그인 성공시 보내줄 url을 정의
    * */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login")  //login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행함, 로그인 form의 action값과 일치하도록
                .defaultSuccessUrl("/")//index로 이동
                .and()
                .oauth2Login()
                .loginPage("/loginForm") //구글 로그인 완료 후 후처리(아래 코드) 필요 상단 주석 참고
                .userInfoEndpoint() //OAuth2 로그인 성공 후 사용자 정보를 가져올 때의 설정들을 담당
                .userService(principalOauth2UserService); //소셜 로그인 성공 시 후속 조치를 진행할 UserService 인터페이스의 구현체를 등록


    }



}
