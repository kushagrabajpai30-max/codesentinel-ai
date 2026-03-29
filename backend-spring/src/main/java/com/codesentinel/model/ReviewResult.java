package com.codesentinel.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * Aggregated review result combining static and AI analysis findings.
 */
@Entity
@Table(name = "review_results")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class ReviewResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private Long prEventId;

    @Builder.Default
    private Integer totalVulnerabilities = 0;

    @Builder.Default
    private Integer criticalCount = 0;

    @Builder.Default
    private Integer highCount = 0;

    @Builder.Default
    private Integer mediumCount = 0;

    @Builder.Default
    private Integer lowCount = 0;

    @Builder.Default
    private Integer staticFindings = 0;

    @Builder.Default
    private Integer aiFindings = 0;

    private Double overallRiskScore;

    @Column(columnDefinition = "TEXT")
    private String simulatedPrComment;

    @Column(nullable = false)
    @Builder.Default
    private LocalDateTime reviewCompletedAt = LocalDateTime.now();
}
