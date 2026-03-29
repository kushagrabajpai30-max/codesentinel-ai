package com.codesentinel.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

/**
 * Maps the GitHub Pull Request webhook JSON payload.
 * Only relevant fields are extracted; the rest are ignored.
 */
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class WebhookPayloadDTO {

    private String action;
    private Integer number;

    @JsonProperty("pull_request")
    private PullRequestInfo pullRequest;

    private Repository repository;
    private Sender sender;

    @Getter @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PullRequestInfo {
        private String title;

        @JsonProperty("html_url")
        private String htmlUrl;

        private Head head;
        private Base base;

        @Getter @Setter
        @NoArgsConstructor
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Head {
            private String sha;
            private String ref;
        }

        @Getter @Setter
        @NoArgsConstructor
        @JsonIgnoreProperties(ignoreUnknown = true)
        public static class Base {
            private String sha;
            private String ref;
        }
    }

    @Getter @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Repository {
        @JsonProperty("full_name")
        private String fullName;
    }

    @Getter @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Sender {
        private String login;
    }
}
