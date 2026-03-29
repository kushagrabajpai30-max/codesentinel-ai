package com.codesentinel.controller;

import com.codesentinel.dto.ReviewResultDTO;
import com.codesentinel.dto.VulnerabilityDTO;
import com.codesentinel.model.*;
import com.codesentinel.repository.*;
import com.codesentinel.service.PrProcessingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Provides REST endpoints for querying review results and manually triggering reviews.
 */
@RestController
@RequestMapping("/api/reviews")
@RequiredArgsConstructor
@Slf4j
public class ReviewController {

    private final PullRequestEventRepository prEventRepository;
    private final ReviewResultRepository reviewResultRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final PrProcessingService prProcessingService;

    /**
     * GET /api/reviews
     * Lists all review results ordered by most recent.
     */
    @GetMapping
    public ResponseEntity<List<ReviewResultDTO>> listReviews() {
        List<ReviewResult> results = reviewResultRepository.findAllByOrderByReviewCompletedAtDesc();
        List<ReviewResultDTO> dtos = results.stream()
                .map(this::toReviewResultDTO)
                .toList();
        return ResponseEntity.ok(dtos);
    }

    /**
     * GET /api/reviews/{id}
     * Gets a specific review result with its vulnerabilities.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ReviewResultDTO> getReview(@PathVariable Long id) {
        return reviewResultRepository.findById(id)
                .map(result -> {
                    ReviewResultDTO dto = toReviewResultDTO(result);
                    List<VulnerabilityDTO> vulns = vulnerabilityRepository
                            .findByPrEventId(result.getPrEventId())
                            .stream()
                            .map(this::toVulnerabilityDTO)
                            .toList();
                    dto.setVulnerabilities(vulns);
                    return ResponseEntity.ok(dto);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/reviews/{id}/vulnerabilities
     * Gets all vulnerabilities for a specific review.
     */
    @GetMapping("/{id}/vulnerabilities")
    public ResponseEntity<List<VulnerabilityDTO>> getVulnerabilities(@PathVariable Long id) {
        return reviewResultRepository.findById(id)
                .map(result -> {
                    List<VulnerabilityDTO> vulns = vulnerabilityRepository
                            .findByPrEventId(result.getPrEventId())
                            .stream()
                            .map(this::toVulnerabilityDTO)
                            .toList();
                    return ResponseEntity.ok(vulns);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/reviews/events
     * Returns all PR events and their statuses.
     */
    @GetMapping("/events")
    public ResponseEntity<List<PullRequestEvent>> listEvents() {
        return ResponseEntity.ok(prEventRepository.findAllByOrderByReceivedAtDesc());
    }

    /**
     * POST /api/reviews/trigger
     * Manually triggers a code review using mock PR data (for demo/testing).
     */
    @PostMapping("/trigger")
    public ResponseEntity<Map<String, Object>> triggerReview(
            @RequestParam(defaultValue = "demo-user/sample-repo") String repo,
            @RequestParam(defaultValue = "42") Integer prNumber) {

        log.info("Manual trigger: {}#{}", repo, prNumber);

        PullRequestEvent event = PullRequestEvent.builder()
                .prNumber(prNumber)
                .repoFullName(repo)
                .action("opened")
                .headSha("abc123def456")
                .baseSha("000000000000")
                .prTitle("feat: Add user authentication service")
                .prUrl("https://github.com/" + repo + "/pull/" + prNumber)
                .senderLogin("demo-user")
                .status(ReviewStatus.PENDING)
                .build();

        event = prEventRepository.save(event);

        // Process synchronously for demo
        prProcessingService.processEvent(event);

        // Fetch the result
        ReviewResult result = reviewResultRepository.findByPrEventId(event.getId()).orElse(null);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of(
                        "message", "Review completed",
                        "eventId", event.getId(),
                        "reviewId", result != null ? result.getId() : "N/A",
                        "totalVulnerabilities", result != null ? result.getTotalVulnerabilities() : 0,
                        "riskScore", result != null ? result.getOverallRiskScore() : 0,
                        "status", event.getStatus().name()
                ));
    }

    // ── DTO Mappers ──────────────────────────────────────────────────

    private ReviewResultDTO toReviewResultDTO(ReviewResult result) {
        PullRequestEvent event = prEventRepository.findById(result.getPrEventId()).orElse(null);

        return ReviewResultDTO.builder()
                .id(result.getId())
                .prEventId(result.getPrEventId())
                .prNumber(event != null ? event.getPrNumber() : null)
                .repoFullName(event != null ? event.getRepoFullName() : null)
                .prTitle(event != null ? event.getPrTitle() : null)
                .status(event != null ? event.getStatus() : null)
                .totalVulnerabilities(result.getTotalVulnerabilities())
                .criticalCount(result.getCriticalCount())
                .highCount(result.getHighCount())
                .mediumCount(result.getMediumCount())
                .lowCount(result.getLowCount())
                .staticFindings(result.getStaticFindings())
                .aiFindings(result.getAiFindings())
                .overallRiskScore(result.getOverallRiskScore())
                .simulatedPrComment(result.getSimulatedPrComment())
                .reviewCompletedAt(result.getReviewCompletedAt())
                .build();
    }

    private VulnerabilityDTO toVulnerabilityDTO(Vulnerability v) {
        return VulnerabilityDTO.builder()
                .id(v.getId())
                .file(v.getFile())
                .lineNumber(v.getLineNumber())
                .vulnerability(v.getVulnerability())
                .severity(v.getSeverity())
                .issue(v.getIssue())
                .fix(v.getFix())
                .explanation(v.getExplanation())
                .owasp(v.getOwaspMapping())
                .source(v.getSource())
                .build();
    }
}
