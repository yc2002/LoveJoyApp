package com.example.demo.appuser;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public interface AppUserRepository
        extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE AppUser u " +
            "SET u.enabled = TRUE WHERE u.email = ?1")
    int enableAppUser(String email);

    @Query("SELECT u FROM AppUser u WHERE u.verificaton_code = ?1")
    public AppUser findByVerificationCode(String code);

    @Query("SELECT u FROM AppUser u WHERE u.email = ?1")
    public AppUser getByEmail(String email);

    @Query("UPDATE AppUser u SET u.verificaton_code = ?1 WHERE u.email = ?2")
    @Modifying
    public void updateVertificationCodeByEmail(String code,String email);


    @Query("UPDATE AppUser u SET u.failedAttempt = ?1 WHERE u.email = ?2")
    @Modifying
    public void updateFailedAttempts(int failAttempts, String email);

    public AppUser findByResetPasswordToken(String token);

    @Query("SELECT u FROM AppUser u WHERE u.email = :email")
    public AppUser getAppUserByEmail(@Param("email") String email);
}
