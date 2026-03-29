package com.codesentinel.service;

import com.codesentinel.dto.AiAnalysisRequestDTO;
import com.codesentinel.dto.AiAnalysisResponseDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * REST client for communicating with the Python AI engine (FastAPI).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AiEngineClient {

    private final RestTemplate restTemplate;

    @Value("${codesentinel.ai-engine.base-url}")
    private String aiEngineBaseUrl;

    /**
     * Sends code diffs to the AI engine for vulnerability analysis.
     *
     * @param request the analysis request containing file diffs
     * @return the AI-generated findings, or null if the engine is unavailable
     */
    public AiAnalysisResponseDTO analyze(AiAnalysisRequestDTO request) {
        String url = aiEngineBaseUrl + "/api/analyze";
        log.info("Calling AI engine at {} with {} diffs", url, request.getDiffs().size());

        try {
            AiAnalysisResponseDTO response = restTemplate.postForObject(
                    url, request, AiAnalysisResponseDTO.class);

            if (response != null && response.isSuccess()) {
                log.info("AI engine returned {} findings",
                        response.getFindings() != null ? response.getFindings().size() : 0);
            } else {
                log.warn("AI engine returned unsuccessful response: {}",
                        response != null ? response.getMessage() : "null");
            }

            return response;
        } catch (RestClientException e) {
            log.error("Failed to call AI engine: {}", e.getMessage());
            throw new RuntimeException("AI engine communication failed", e);
        }
    }

    /**
     * Checks if the AI engine is reachable.
     */
    public boolean isHealthy() {
        try {
            String url = aiEngineBaseUrl + "/api/health";
            String response = restTemplate.getForObject(url, String.class);
            return response != null;
        } catch (Exception e) {
            return false;
        }
    }
}
