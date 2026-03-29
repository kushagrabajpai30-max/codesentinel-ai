package com.codesentinel.service;

import com.codesentinel.model.*;
import com.codesentinel.repository.ReviewResultRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Aggregates static and AI analysis results, calculates risk scores,
 * generates simulated PR comments, and persists the final review result.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ReviewAggregatorService {

    private final ReviewResultRepository reviewResultRepository;

    /**
     * Aggregates all vulnerability findings for a PR event and saves the review result.
     */
    public ReviewResult aggregateAndSave(PullRequestEvent event, List<Vulnerability> vulnerabilities) {
        int criticalCount = countBySeverity(vulnerabilities, Severity.CRITICAL);
        int highCount = countBySeverity(vulnerabilities, Severity.HIGH);
        int mediumCount = countBySeverity(vulnerabilities, Severity.MEDIUM);
        int lowCount = countBySeverity(vulnerabilities, Severity.LOW);

        int staticFindings = countBySource(vulnerabilities, DetectionSource.STATIC);
        int aiFindings = countBySource(vulnerabilities, DetectionSource.AI);

        double riskScore = calculateRiskScore(criticalCount, highCount, mediumCount, lowCount);

        String prComment = generateSimulatedPrComment(event, vulnerabilities, riskScore);

        ReviewResult result = ReviewResult.builder()
                .prEventId(event.getId())
                .totalVulnerabilities(vulnerabilities.size())
                .criticalCount(criticalCount)
                .highCount(highCount)
                .mediumCount(mediumCount)
                .lowCount(lowCount)
                .staticFindings(staticFindings)
                .aiFindings(aiFindings)
                .overallRiskScore(riskScore)
                .simulatedPrComment(prComment)
                .reviewCompletedAt(LocalDateTime.now())
                .build();

        result = reviewResultRepository.save(result);
        log.info("Saved review result #{} for PR event #{}: risk={}, vulns={}",
                result.getId(), event.getId(), riskScore, vulnerabilities.size());

        return result;
    }

    /**
     * Calculates a risk score (0-100) based on vulnerability counts and severity.
     */
    private double calculateRiskScore(int critical, int high, int medium, int low) {
        double rawScore = (critical * 40.0) + (high * 25.0) + (medium * 10.0) + (low * 3.0);
        return Math.min(100.0, rawScore);
    }

    /**
     * Generates a simulated GitHub PR comment summarizing the security review.
     */
    private String generateSimulatedPrComment(PullRequestEvent event,
                                               List<Vulnerability> vulnerabilities,
                                               double riskScore) {
        StringBuilder sb = new StringBuilder();

        sb.append("## 🛡️ CodeSentinel AI — Security Review\n\n");
        sb.append(String.format("**Repository:** `%s`\n", event.getRepoFullName()));
        sb.append(String.format("**PR #%d:** %s\n", event.getPrNumber(), event.getPrTitle()));
        sb.append(String.format("**Risk Score:** %.0f/100 %s\n\n", riskScore, getRiskEmoji(riskScore)));

        // Summary table
        sb.append("### Summary\n\n");
        sb.append("| Severity | Count |\n");
        sb.append("|----------|-------|\n");

        int critical = countBySeverity(vulnerabilities, Severity.CRITICAL);
        int high = countBySeverity(vulnerabilities, Severity.HIGH);
        int medium = countBySeverity(vulnerabilities, Severity.MEDIUM);
        int low = countBySeverity(vulnerabilities, Severity.LOW);

        if (critical > 0) sb.append(String.format("| 🔴 CRITICAL | %d |\n", critical));
        if (high > 0) sb.append(String.format("| 🟠 HIGH | %d |\n", high));
        if (medium > 0) sb.append(String.format("| 🟡 MEDIUM | %d |\n", medium));
        if (low > 0) sb.append(String.format("| 🟢 LOW | %d |\n", low));

        sb.append(String.format("\n**Total: %d vulnerabilities found**\n\n", vulnerabilities.size()));

        // Detailed findings
        if (!vulnerabilities.isEmpty()) {
            sb.append("### Findings\n\n");

            // Group by file
            vulnerabilities.stream()
                    .collect(Collectors.groupingBy(Vulnerability::getFile))
                    .forEach((file, fileVulns) -> {
                        sb.append(String.format("#### 📄 `%s`\n\n", file));
                        for (Vulnerability v : fileVulns) {
                            sb.append(String.format("- **%s** %s (`%s` — %s)\n",
                                    getSeverityIcon(v.getSeverity()),
                                    v.getVulnerability(),
                                    v.getSeverity(),
                                    v.getOwaspMapping()));
                            sb.append(String.format("  - **Issue:** %s\n", v.getIssue()));
                            sb.append(String.format("  - **Fix:** %s\n", v.getFix()));
                            if (v.getLineNumber() != null) {
                                sb.append(String.format("  - **Line:** %d\n", v.getLineNumber()));
                            }
                            sb.append("\n");
                        }
                    });
        }

        sb.append("---\n");
        sb.append("*Generated by CodeSentinel AI • Static Analysis + AI-Powered Review*\n");

        return sb.toString();
    }

    private String getRiskEmoji(double riskScore) {
        if (riskScore >= 75) return "🔴 CRITICAL RISK";
        if (riskScore >= 50) return "🟠 HIGH RISK";
        if (riskScore >= 25) return "🟡 MODERATE RISK";
        return "🟢 LOW RISK";
    }

    private String getSeverityIcon(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🟢";
        };
    }

    private int countBySeverity(List<Vulnerability> vulnerabilities, Severity severity) {
        return (int) vulnerabilities.stream()
                .filter(v -> v.getSeverity() == severity)
                .count();
    }

    private int countBySource(List<Vulnerability> vulnerabilities, DetectionSource source) {
        return (int) vulnerabilities.stream()
                .filter(v -> v.getSource() == source)
                .count();
    }
}
