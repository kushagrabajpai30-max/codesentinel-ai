package com.codesentinel.dto;

import com.codesentinel.model.ReviewStatus;
import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Aggregated review result DTO with vulnerability details.
 */
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class ReviewResultDTO {

    private Long id;
    private Long prEventId;
    private Integer prNumber;
    private String repoFullName;
    private String prTitle;
    private ReviewStatus status;

    private Integer totalVulnerabilities;
    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    private Integer staticFindings;
    private Integer aiFindings;
    private Double overallRiskScore;

    private String simulatedPrComment;
    private LocalDateTime reviewCompletedAt;

    private List<VulnerabilityDTO> vulnerabilities;
}
