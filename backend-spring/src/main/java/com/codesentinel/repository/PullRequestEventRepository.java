package com.codesentinel.repository;

import com.codesentinel.model.PullRequestEvent;
import com.codesentinel.model.ReviewStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PullRequestEventRepository extends JpaRepository<PullRequestEvent, Long> {

    List<PullRequestEvent> findByStatus(ReviewStatus status);

    List<PullRequestEvent> findByRepoFullNameOrderByReceivedAtDesc(String repoFullName);

    List<PullRequestEvent> findAllByOrderByReceivedAtDesc();

    boolean existsByRepoFullNameAndPrNumberAndHeadSha(String repoFullName, Integer prNumber, String headSha);
}
