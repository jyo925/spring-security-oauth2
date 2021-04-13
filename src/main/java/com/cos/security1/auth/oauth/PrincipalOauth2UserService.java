package com.cos.security1.auth.oauth;

import com.cos.security1.auth.PrincipalDetails;
import com.cos.security1.auth.oauth.provider.FacebookUserInfo;
import com.cos.security1.auth.oauth.provider.GoogleUserInfo;
import com.cos.security1.auth.oauth.provider.NaverUserInfo;
import com.cos.security1.auth.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

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
        /*log.info("userRequest getAccessToken:   " + userRequest.getAccessToken());
        //registrationid로 어떤 OAuth로 로그인 했는지 확인 가능 -> google, facebook...
        log.info("userRequest getClientRegistration:   " + userRequest.getClientRegistration());
        log.info("userRequest getAdditionalParameters:   " + userRequest.getAdditionalParameters());*/

        OAuth2User oAuth2User = super.loadUser(userRequest);
        
        //구글로그인 버튼 클릭 -> 구글 로그인창 -> 로그인 완료 -> code를 리턴(OAuth Client 라이브러리가 받음) 
        // -> Access Token 요청, 여기까지 userRequest 정보
        //userReqeust 정보를 이용해서 회원 프로필을 받아야 한다.(loadUser함수 이용, 호출) -> 회원 프로필 취득
        log.info("userRequest getAttributes:   " + oAuth2User.getAttributes()); //이 정보만 있으면 됨

        //강제 회원 가입
        OAuth2UserInfo oAuth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            log.info("네이버 로그인 요청");
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        } else {
            log.info("구글, 페이스북, 네이버만 지원합니다.");
        }

/*        String provider = userRequest.getClientRegistration().getRegistrationId(); //google
        String providerId = oAuth2User.getAttribute("sub"); //sub는 구글에만 있는 속성임... -> 수정
        String email = oAuth2User.getAttribute("email");
        String username = provider + "_" + providerId; //google_104654864~~~~
        //필요 없지만 생성
        String password = bCryptPasswordEncoder.encode("지윤지윤"); //의미없는 패스워드임
        String role = "ROLE_USER";*/

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String email = oAuth2UserInfo.getEmail();
        String username = provider+ "_" + providerId;
        String password = bCryptPasswordEncoder.encode("지윤지윤");
        String role = "ROLE_USER";

        //미가입 회원 처리
        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .prividerId(providerId)
                    .provider(provider)
                    .build();
            userRepository.save(userEntity);
        } else {
            log.info("로그인 이력이 있는 회원입니다.");
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
