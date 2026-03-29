package com.codesentinel.controller;

import com.codesentinel.dto.WebhookPayloadDTO;
import com.codesentinel.model.PullRequestEvent;
import com.codesentinel.service.WebhookService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Receives GitHub webhook events for Pull Requests.
 */
@RestController
@RequestMapping("/api/webhook")
@RequiredArgsConstructor
@Slf4j
public class WebhookController {

    private final WebhookService webhookService;
    private final ObjectMapper objectMapper;

    /**
     * POST /api/webhook
     * Accepts a GitHub PR webhook payload, validates the signature,
     * and enqueues the event for async processing.
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> handleWebhook(
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", required = false) String event,
            @RequestHeader(value = "X-GitHub-Delivery", required = false) String deliveryId,
            @RequestBody String rawPayload) {

        log.info("Received webhook: event={}, delivery={}", event, deliveryId);

        // Validate signature (skip in dev if no signature provided)
        if (signature != null && !webhookService.validateSignature(signature, rawPayload)) {
            log.warn("Invalid webhook signature for delivery {}", deliveryId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Invalid signature"));
        }

        // Only process pull_request events
        if (event != null && !"pull_request".equals(event)) {
            log.info("Ignoring non-PR event: {}", event);
            return ResponseEntity.ok(Map.of("message", "Event ignored", "event", event));
        }

        try {
            WebhookPayloadDTO payload = objectMapper.readValue(rawPayload, WebhookPayloadDTO.class);

            PullRequestEvent prEvent = webhookService.processWebhook(payload);

            if (prEvent == null) {
                return ResponseEntity.ok(Map.of(
                        "message", "Event skipped (duplicate or non-actionable action)"));
            }

            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(Map.of(
                            "message", "PR event accepted for review",
                            "eventId", prEvent.getId(),
                            "prNumber", prEvent.getPrNumber(),
                            "repo", prEvent.getRepoFullName(),
                            "status", prEvent.getStatus().name()
                    ));
        } catch (Exception e) {
            log.error("Failed to parse webhook payload", e);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid payload format"));
        }
    }

    /**
     * GET /api/webhook/health
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "service", "CodeSentinel AI Backend"
        ));
    }
}
