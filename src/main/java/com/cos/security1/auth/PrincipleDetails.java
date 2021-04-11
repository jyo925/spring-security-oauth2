package com.cos.security1.auth;

// 시큐리티가 /login 요청이 오면 낚아채서 로그인을 진행시킴
// 로그인 진행 완료 시 session을 만들어 주는데
// 시큐리티가 가지고 있는 자신만의 세션 공간이 있음
// SecurityContextHoler에 session 정보를 저장함
// 이 때 여기에 들어갈 수 있는 객체 타입이 Authentication
// Authentication 안에는 User 정보가 있어야 함
// User 정보의 타입은 UserDetails

// Security Session -> Authentication -> UserDetails

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipleDetails implements UserDetails {

    private User user; //콤포지션

    public PrincipleDetails(User user) {
        this.user = user;
    }

    //해당 유저 권한 리턴
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {

        //1년 동안 로그인 이력이 없으면 휴면 계정으로 등록 -> false 반환
        //현재 시간 - 마지막 로그인 시간 등...
        return true;
    }
}
