package com.codesentinel.service;

import com.codesentinel.dto.WebhookPayloadDTO;
import com.codesentinel.model.PullRequestEvent;
import com.codesentinel.model.ReviewStatus;
import com.codesentinel.repository.PullRequestEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Handles webhook payload validation and PR event creation.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookService {

    private final PullRequestEventRepository prEventRepository;
    private final EventQueueService eventQueueService;

    @Value("${codesentinel.webhook.secret}")
    private String webhookSecret;

    /**
     * Validates the webhook signature using HMAC-SHA256.
     */
    public boolean validateSignature(String signature, String payload) {
        if (signature == null || !signature.startsWith("sha256=")) {
            log.warn("Missing or invalid webhook signature format");
            return false;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(
                    webhookSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hash = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            String computed = "sha256=" + HexFormat.of().formatHex(hash);

            boolean valid = computed.equalsIgnoreCase(signature);
            if (!valid) {
                log.warn("Webhook signature mismatch");
            }
            return valid;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("Error validating webhook signature", e);
            return false;
        }
    }

    /**
     * Processes the webhook payload: creates a PR event and enqueues it for analysis.
     */
    public PullRequestEvent processWebhook(WebhookPayloadDTO payload) {
        // Only process "opened" and "synchronize" (new push) actions
        String action = payload.getAction();
        if (!"opened".equals(action) && !"synchronize".equals(action) && !"reopened".equals(action)) {
            log.info("Ignoring PR action: {}", action);
            return null;
        }

        // Deduplicate by repo + PR number + head sha
        String repoFullName = payload.getRepository().getFullName();
        Integer prNumber = payload.getNumber();
        String headSha = payload.getPullRequest().getHead().getSha();

        if (prEventRepository.existsByRepoFullNameAndPrNumberAndHeadSha(repoFullName, prNumber, headSha)) {
            log.info("Duplicate event for {}#{} @ {}, skipping", repoFullName, prNumber, headSha);
            return null;
        }

        PullRequestEvent event = PullRequestEvent.builder()
                .prNumber(prNumber)
                .repoFullName(repoFullName)
                .action(action)
                .headSha(headSha)
                .baseSha(payload.getPullRequest().getBase().getSha())
                .prTitle(payload.getPullRequest().getTitle())
                .prUrl(payload.getPullRequest().getHtmlUrl())
                .senderLogin(payload.getSender().getLogin())
                .status(ReviewStatus.PENDING)
                .build();

        event = prEventRepository.save(event);
        log.info("Created PR event #{} for {}#{}", event.getId(), repoFullName, prNumber);

        // Enqueue for async processing
        eventQueueService.enqueue(event);

        return event;
    }
}
