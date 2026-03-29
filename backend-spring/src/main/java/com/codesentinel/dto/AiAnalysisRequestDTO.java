package com.codesentinel.dto;

import lombok.*;
import java.util.List;

/**
 * Request body sent to the Python AI engine for analysis.
 */
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class AiAnalysisRequestDTO {

    private Long prEventId;
    private String repoFullName;
    private Integer prNumber;

    private List<FileDiff> diffs;

    @Getter @Setter
    @NoArgsConstructor @AllArgsConstructor
    @Builder
    public static class FileDiff {
        private String filename;
        private String patch;
        private String status; // added, modified, removed
        private String language;
    }
}
