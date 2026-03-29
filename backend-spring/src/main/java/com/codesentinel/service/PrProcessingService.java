package com.codesentinel.service;

import com.codesentinel.dto.AiAnalysisRequestDTO;
import com.codesentinel.dto.AiAnalysisResponseDTO;
import com.codesentinel.model.*;
import com.codesentinel.repository.PullRequestEventRepository;
import com.codesentinel.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Background worker that consumes PR events from the queue and orchestrates
 * the full analysis pipeline: diff extraction → static analysis → AI analysis → aggregation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PrProcessingService {

    private final EventQueueService eventQueueService;
    private final PullRequestEventRepository prEventRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final GitHubApiService gitHubApiService;
    private final StaticAnalysisService staticAnalysisService;
    private final AiEngineClient aiEngineClient;
    private final ReviewAggregatorService reviewAggregatorService;

    /**
     * Polls the event queue every 2 seconds and processes events.
     */
    @Scheduled(fixedDelay = 2000)
    public void pollAndProcess() {
        PullRequestEvent event = eventQueueService.dequeue(500);
        if (event != null) {
            processEvent(event);
        }
    }

    /**
     * Processes a single PR event through the full pipeline.
     */
    public void processEvent(PullRequestEvent event) {
        log.info("▶ Processing PR event #{}: {}#{}", event.getId(),
                event.getRepoFullName(), event.getPrNumber());

        // Update status to PROCESSING
        event.setStatus(ReviewStatus.PROCESSING);
        prEventRepository.save(event);

        try {
            // Step 1: Fetch diffs (mock GitHub API)
            List<Map<String, String>> diffs = gitHubApiService.fetchPullRequestDiffs(
                    event.getRepoFullName(), event.getPrNumber());
            log.info("  Fetched {} file diffs", diffs.size());

            // Step 2: Run static analysis
            List<Vulnerability> staticVulns = staticAnalysisService.analyze(event.getId(), diffs);
            log.info("  Static analysis found {} vulnerabilities", staticVulns.size());
            vulnerabilityRepository.saveAll(staticVulns);

            // Step 3: Send to AI engine
            List<Vulnerability> aiVulns = new ArrayList<>();
            try {
                AiAnalysisRequestDTO aiRequest = buildAiRequest(event, diffs);
                AiAnalysisResponseDTO aiResponse = aiEngineClient.analyze(aiRequest);

                if (aiResponse != null && aiResponse.isSuccess() && aiResponse.getFindings() != null) {
                    aiVulns = convertAiFindings(event.getId(), aiResponse.getFindings());
                    log.info("  AI analysis found {} vulnerabilities", aiVulns.size());
                    vulnerabilityRepository.saveAll(aiVulns);
                }
            } catch (Exception e) {
                log.warn("  AI engine unavailable, continuing with static analysis only: {}", e.getMessage());
            }

            // Step 4: Aggregate results
            List<Vulnerability> allVulns = new ArrayList<>(staticVulns);
            allVulns.addAll(aiVulns);
            reviewAggregatorService.aggregateAndSave(event, allVulns);

            // Update status to COMPLETED
            event.setStatus(ReviewStatus.COMPLETED);
            event.setProcessedAt(LocalDateTime.now());
            prEventRepository.save(event);

            log.info("✓ Completed PR event #{}: {} total vulnerabilities",
                    event.getId(), allVulns.size());

        } catch (Exception e) {
            log.error("✗ Failed processing PR event #{}", event.getId(), e);
            event.setStatus(ReviewStatus.FAILED);
            event.setProcessedAt(LocalDateTime.now());
            prEventRepository.save(event);
        }
    }

    private AiAnalysisRequestDTO buildAiRequest(PullRequestEvent event, List<Map<String, String>> diffs) {
        List<AiAnalysisRequestDTO.FileDiff> fileDiffs = diffs.stream()
                .map(d -> AiAnalysisRequestDTO.FileDiff.builder()
                        .filename(d.get("filename"))
                        .patch(d.get("patch"))
                        .status(d.getOrDefault("status", "modified"))
                        .language(detectLanguage(d.get("filename")))
                        .build())
                .toList();

        return AiAnalysisRequestDTO.builder()
                .prEventId(event.getId())
                .repoFullName(event.getRepoFullName())
                .prNumber(event.getPrNumber())
                .diffs(fileDiffs)
                .build();
    }

    private List<Vulnerability> convertAiFindings(Long prEventId, List<AiAnalysisResponseDTO.AiFinding> findings) {
        return findings.stream()
                .map(f -> Vulnerability.builder()
                        .prEventId(prEventId)
                        .file(f.getFile())
                        .lineNumber(f.getLineNumber())
                        .vulnerability(f.getVulnerability())
                        .severity(parseSeverity(f.getSeverity()))
                        .issue(f.getIssue())
                        .fix(f.getFix())
                        .explanation(f.getExplanation())
                        .owaspMapping(f.getOwasp())
                        .source(DetectionSource.AI)
                        .build())
                .toList();
    }

    private Severity parseSeverity(String severity) {
        try {
            return Severity.valueOf(severity.toUpperCase());
        } catch (Exception e) {
            return Severity.MEDIUM;
        }
    }

    private String detectLanguage(String filename) {
        if (filename == null) return "unknown";
        if (filename.endsWith(".java")) return "java";
        if (filename.endsWith(".py")) return "python";
        if (filename.endsWith(".js")) return "javascript";
        if (filename.endsWith(".ts")) return "typescript";
        if (filename.endsWith(".go")) return "go";
        if (filename.endsWith(".rb")) return "ruby";
        if (filename.endsWith(".php")) return "php";
        if (filename.endsWith(".cs")) return "csharp";
        return "unknown";
    }
}
