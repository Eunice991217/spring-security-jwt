package com.example.securityprac.repository;

import com.example.securityprac.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);

    // 특정한 회원 조회
    UserEntity findByUsername(String username);

}
