package com.example.demo.request;

import com.example.demo.appuser.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface EvaluationRequestRepository extends JpaRepository<EvaluationRequest, Long> {

    @Query("SELECT r FROM EvaluationRequest r WHERE r.appUser = ?1")
    public EvaluationRequest findEvaluationRequestByAppUser(AppUser appUser);

    @Query("SELECT r FROM EvaluationRequest  r WHERE r.id = ?1")
    public EvaluationRequest findEvaluationRequestById(Long id);

    @Query("UPDATE EvaluationRequest r SET r.open = ?1 WHERE r.id=?2")
    @Modifying
    public void updateOpen(Boolean status);
}
