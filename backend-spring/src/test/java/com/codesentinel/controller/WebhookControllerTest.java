package com.codesentinel.controller;

import com.codesentinel.service.WebhookService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(WebhookController.class)
class WebhookControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private WebhookService webhookService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Health endpoint should return UP")
    void healthCheck() throws Exception {
        mockMvc.perform(get("/api/webhook/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("CodeSentinel AI Backend"));
    }

    @Test
    @DisplayName("Webhook should ignore non-PR events")
    void shouldIgnoreNonPrEvents() throws Exception {
        mockMvc.perform(post("/api/webhook")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-GitHub-Event", "push")
                        .content("{\"action\": \"completed\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Event ignored"));
    }

    @Test
    @DisplayName("Webhook should reject invalid signature")
    void shouldRejectInvalidSignature() throws Exception {
        org.mockito.Mockito.when(webhookService.validateSignature(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString()
        )).thenReturn(false);

        mockMvc.perform(post("/api/webhook")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Hub-Signature-256", "sha256=invalid")
                        .header("X-GitHub-Event", "pull_request")
                        .content(getSamplePayload()))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Invalid signature"));
    }

    @Test
    @DisplayName("Webhook should accept valid PR payload")
    void shouldAcceptValidPrPayload() throws Exception {
        com.codesentinel.model.PullRequestEvent mockEvent =
                com.codesentinel.model.PullRequestEvent.builder()
                        .id(1L)
                        .prNumber(42)
                        .repoFullName("user/repo")
                        .status(com.codesentinel.model.ReviewStatus.PENDING)
                        .build();

        org.mockito.Mockito.when(webhookService.processWebhook(
                org.mockito.ArgumentMatchers.any()
        )).thenReturn(mockEvent);

        mockMvc.perform(post("/api/webhook")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-GitHub-Event", "pull_request")
                        .content(getSamplePayload()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value("PR event accepted for review"))
                .andExpect(jsonPath("$.eventId").value(1))
                .andExpect(jsonPath("$.prNumber").value(42));
    }

    private String getSamplePayload() {
        return """
                {
                    "action": "opened",
                    "number": 42,
                    "pull_request": {
                        "title": "feat: Add auth",
                        "html_url": "https://github.com/user/repo/pull/42",
                        "head": { "sha": "abc123", "ref": "feature/auth" },
                        "base": { "sha": "def456", "ref": "main" }
                    },
                    "repository": { "full_name": "user/repo" },
                    "sender": { "login": "testuser" }
                }
                """;
    }
}
