package com.codesentinel.dto;

import lombok.*;
import java.util.List;

/**
 * Response body from the Python AI engine containing vulnerability findings.
 */
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class AiAnalysisResponseDTO {

    private boolean success;
    private String message;
    private List<AiFinding> findings;

    @Getter @Setter
    @NoArgsConstructor @AllArgsConstructor
    @Builder
    public static class AiFinding {
        private String file;
        private Integer lineNumber;
        private String vulnerability;
        private String severity;
        private String issue;
        private String fix;
        private String explanation;
        private String owasp;
    }
}
