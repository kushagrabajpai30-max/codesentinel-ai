package com.codesentinel.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

/**
 * Represents a GitHub Pull Request event received via webhook.
 */
@Entity
@Table(name = "pull_request_events")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class PullRequestEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Integer prNumber;

    @Column(nullable = false)
    private String repoFullName;

    @Column(nullable = false)
    private String action;

    private String headSha;
    private String baseSha;
    private String prTitle;
    private String prUrl;
    private String senderLogin;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private ReviewStatus status = ReviewStatus.PENDING;

    @Column(nullable = false)
    @Builder.Default
    private LocalDateTime receivedAt = LocalDateTime.now();

    private LocalDateTime processedAt;
}
