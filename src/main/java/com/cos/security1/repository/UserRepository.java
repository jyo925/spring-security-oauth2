package com.cos.security1.repository;


import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

//CRUD 함수를 JpaRepo가 들고 있음
//@Repository 어노테이션 없어도 JpaRepository를 상속 받으면 빈 등록 된다.
public interface UserRepository extends JpaRepository<User, Integer> {
    
    //쿼리 메소드
    //쿼리 메소드는 스프링 데이터 JPA의 핵심적인 기능중 하나로 메소드 이름으로 쿼리를 생성할 수 있다
    User findByUsername(String username);
}
