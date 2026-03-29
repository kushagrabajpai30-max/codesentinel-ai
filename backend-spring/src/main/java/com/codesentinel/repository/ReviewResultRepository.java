package com.codesentinel.repository;

import com.codesentinel.model.ReviewResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.List;

@Repository
public interface ReviewResultRepository extends JpaRepository<ReviewResult, Long> {

    Optional<ReviewResult> findByPrEventId(Long prEventId);

    List<ReviewResult> findAllByOrderByReviewCompletedAtDesc();
}
