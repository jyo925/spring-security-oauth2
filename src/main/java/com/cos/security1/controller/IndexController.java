package com.cos.security1.controller;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Log
@Controller
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    //일반 로그인
    //파라미터를 UserDetails 말고도 PrincipalDetails로 받아도 됨
    //구글 로그인 시 cannot be cast to com.cos.security1.auth.PrincipalDetails 에러 발생 -> 수정 필요
    @GetMapping("/test/login")
    public @ResponseBody
    String testLogin(Authentication authentication,
                     @AuthenticationPrincipal UserDetails userDetails) {

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication: " + principalDetails.getUser());
        log.info("userDetails: " + userDetails.getUsername());

        return "세션 정보 확인하기";

    }

    //구글 로그인
    @GetMapping("/test/oauth/login")
    public @ResponseBody
    String testLogin(Authentication authentication,
                     @AuthenticationPrincipal OAuth2User oAuth) {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

//        PrincipalOauth2UserService의 OAuth2User oAuth2User = super.loadUser(userRequest);랑 같은 정보임
        log.info("oAuth2User: " + oAuth2User.getAttributes());
        log.info("authentication: " + authentication.getPrincipal());
        log.info("oauth: " + oAuth.getAttributes());
        return "세션 정보 확인하기";
    }


    //일반 & OAuth 로그인 통합 수정
    //@AuthenticationPrincipal를 사용하면 
    //UserDetailsService(loadUserByUsername())에서 리턴한 객체를 컨트롤러의 파라미터로 직접 참조 가능
    @GetMapping("/user")
    public @ResponseBody
    String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails: " + principalDetails.getUser());
        return "user";
    }


    @GetMapping({"", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "loginForm";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    //실제 회원 가입 처리
    @PostMapping("/join")
    public String join(User user) {
        log.info(user + "");
        user.setRole("ROLE_USER");
        String rawPw = user.getPassword();
        String encPw = bCryptPasswordEncoder.encode(rawPw); //비밀번호 암호화
        user.setPassword(encPw);
        userRepository.save(user); //회원가입 완료

        return "redirect:/loginForm";
    }
    
    @GetMapping("/admin")
    public @ResponseBody
    String admin() {
        return "admin";
    }


    @GetMapping("/manager")
    public @ResponseBody
    String manager() {
        return "manager";
    }


    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody
    String info() {
        return "개인정보";
    }


    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody
    String data() {
        return "데이터정보";
    }
}
