package com.codesentinel.service;

import com.codesentinel.model.*;
import com.codesentinel.repository.ReviewResultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReviewAggregatorServiceTest {

    @Mock
    private ReviewResultRepository reviewResultRepository;

    @InjectMocks
    private ReviewAggregatorService aggregatorService;

    private PullRequestEvent sampleEvent;

    @BeforeEach
    void setUp() {
        sampleEvent = PullRequestEvent.builder()
                .id(1L)
                .prNumber(42)
                .repoFullName("user/repo")
                .prTitle("feat: Add auth service")
                .action("opened")
                .build();
    }

    @Test
    @DisplayName("Should correctly count vulnerabilities by severity")
    void countBySeverity() {
        List<Vulnerability> vulns = List.of(
                buildVuln(Severity.CRITICAL, DetectionSource.STATIC),
                buildVuln(Severity.HIGH, DetectionSource.STATIC),
                buildVuln(Severity.HIGH, DetectionSource.AI),
                buildVuln(Severity.MEDIUM, DetectionSource.STATIC),
                buildVuln(Severity.LOW, DetectionSource.AI)
        );

        when(reviewResultRepository.save(any())).thenAnswer(inv -> {
            ReviewResult r = inv.getArgument(0);
            r.setId(1L);
            return r;
        });

        ReviewResult result = aggregatorService.aggregateAndSave(sampleEvent, vulns);

        assertThat(result.getTotalVulnerabilities()).isEqualTo(5);
        assertThat(result.getCriticalCount()).isEqualTo(1);
        assertThat(result.getHighCount()).isEqualTo(2);
        assertThat(result.getMediumCount()).isEqualTo(1);
        assertThat(result.getLowCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should correctly count findings by source")
    void countBySource() {
        List<Vulnerability> vulns = List.of(
                buildVuln(Severity.HIGH, DetectionSource.STATIC),
                buildVuln(Severity.HIGH, DetectionSource.STATIC),
                buildVuln(Severity.MEDIUM, DetectionSource.AI)
        );

        when(reviewResultRepository.save(any())).thenAnswer(inv -> {
            ReviewResult r = inv.getArgument(0);
            r.setId(1L);
            return r;
        });

        ReviewResult result = aggregatorService.aggregateAndSave(sampleEvent, vulns);

        assertThat(result.getStaticFindings()).isEqualTo(2);
        assertThat(result.getAiFindings()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should calculate risk score correctly")
    void calculateRiskScore() {
        // 1 critical (40) + 2 high (50) = 90
        List<Vulnerability> vulns = List.of(
                buildVuln(Severity.CRITICAL, DetectionSource.STATIC),
                buildVuln(Severity.HIGH, DetectionSource.STATIC),
                buildVuln(Severity.HIGH, DetectionSource.AI)
        );

        when(reviewResultRepository.save(any())).thenAnswer(inv -> {
            ReviewResult r = inv.getArgument(0);
            r.setId(1L);
            return r;
        });

        ReviewResult result = aggregatorService.aggregateAndSave(sampleEvent, vulns);

        assertThat(result.getOverallRiskScore()).isEqualTo(90.0);
    }

    @Test
    @DisplayName("Risk score should cap at 100")
    void riskScoreCap() {
        List<Vulnerability> vulns = List.of(
                buildVuln(Severity.CRITICAL, DetectionSource.STATIC),
                buildVuln(Severity.CRITICAL, DetectionSource.STATIC),
                buildVuln(Severity.CRITICAL, DetectionSource.AI),
                buildVuln(Severity.HIGH, DetectionSource.STATIC)
        );

        when(reviewResultRepository.save(any())).thenAnswer(inv -> {
            ReviewResult r = inv.getArgument(0);
            r.setId(1L);
            return r;
        });

        ReviewResult result = aggregatorService.aggregateAndSave(sampleEvent, vulns);

        assertThat(result.getOverallRiskScore()).isEqualTo(100.0);
    }

    @Test
    @DisplayName("Should generate simulated PR comment")
    void generatePrComment() {
        List<Vulnerability> vulns = List.of(
                buildVulnWithDetails("SQL Injection", Severity.HIGH,
                        "UserService.java", DetectionSource.STATIC)
        );

        when(reviewResultRepository.save(any())).thenAnswer(inv -> {
            ReviewResult r = inv.getArgument(0);
            r.setId(1L);
            return r;
        });

        ReviewResult result = aggregatorService.aggregateAndSave(sampleEvent, vulns);

        assertThat(result.getSimulatedPrComment()).contains("CodeSentinel AI");
        assertThat(result.getSimulatedPrComment()).contains("SQL Injection");
        assertThat(result.getSimulatedPrComment()).contains("UserService.java");
        assertThat(result.getSimulatedPrComment()).contains("user/repo");
    }

    @Test
    @DisplayName("Should handle empty vulnerabilities list")
    void emptyVulnerabilities() {
        when(reviewResultRepository.save(any())).thenAnswer(inv -> {
            ReviewResult r = inv.getArgument(0);
            r.setId(1L);
            return r;
        });

        ReviewResult result = aggregatorService.aggregateAndSave(sampleEvent, List.of());

        assertThat(result.getTotalVulnerabilities()).isEqualTo(0);
        assertThat(result.getOverallRiskScore()).isEqualTo(0.0);
    }

    private Vulnerability buildVuln(Severity severity, DetectionSource source) {
        return Vulnerability.builder()
                .prEventId(1L)
                .file("Test.java")
                .vulnerability("Test Vulnerability")
                .severity(severity)
                .issue("Test issue")
                .fix("Test fix")
                .source(source)
                .build();
    }

    private Vulnerability buildVulnWithDetails(String name, Severity severity,
                                                String file, DetectionSource source) {
        return Vulnerability.builder()
                .prEventId(1L)
                .file(file)
                .vulnerability(name)
                .severity(severity)
                .issue("Test issue for " + name)
                .fix("Fix for " + name)
                .source(source)
                .build();
    }
}
