package com.cos.security1.auth.oauth;

import lombok.extern.java.Log;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Log
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    //구글로부터 받은 userRequest 데이터에 대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest getAccessToken:   " + userRequest.getAccessToken());
        log.info("userRequest getClientRegistration:   " + userRequest.getClientRegistration());
        log.info("userRequest getAdditionalParameters:   " + userRequest.getAdditionalParameters());
        log.info("userRequest getAttributes:   " + super.loadUser(userRequest).getAttributes()); //이정보만 있으면 됨
        return super.loadUser(userRequest);
    }
}
