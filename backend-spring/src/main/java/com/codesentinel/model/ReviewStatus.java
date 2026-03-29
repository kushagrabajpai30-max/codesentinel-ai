package com.codesentinel.model;

/**
 * Tracks the lifecycle of a PR review event.
 */
public enum ReviewStatus {
    PENDING,
    PROCESSING,
    COMPLETED,
    FAILED
}
