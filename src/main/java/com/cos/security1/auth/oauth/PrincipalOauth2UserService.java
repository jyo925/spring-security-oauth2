package com.cos.security1.auth.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Log
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;


    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    //함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest getAccessToken:   " + userRequest.getAccessToken());

        //registrationid로 어떤 OAuth로 로그인 했는지 확인 가능 -> google
        log.info("userRequest getClientRegistration:   " + userRequest.getClientRegistration());
        log.info("userRequest getAdditionalParameters:   " + userRequest.getAdditionalParameters());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        //구글로그인 버튼 클릭 -> 구글로그인창 -> 로그인완료 -> code를 리턴(OAuth Client 라이브러리가 받음) -> Access Token 요청, 여기까지 userRequest 정보
        //userReqeust 정보를 이용해서 회원 프로필을 받아야 한다.(loadUser함수 이용, 호출) -> 회원프로필 취득
        log.info("userRequest getAttributes:   " + oAuth2User.getAttributes()); //이정보만 있으면 됨

        //강제 회원 가입 시키기
        String provider = userRequest.getClientRegistration().getClientId(); //google
        String providerId = oAuth2User.getAttribute("sub");
        String email = oAuth2User.getAttribute("email");
        String username = provider + "_" + providerId; //google_104654864~~~~
        //필요 없지만 생성
        String password = bCryptPasswordEncoder.encode("지윤지윤");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        //가입되어있지 않다면...
        if (userEntity == null) {
            log.info("구글 로그인이 최조입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .prividerId(providerId)
                    .provider(provider)
                    .build();
            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
