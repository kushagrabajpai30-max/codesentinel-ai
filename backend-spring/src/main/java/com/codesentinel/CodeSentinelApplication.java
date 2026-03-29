package com.codesentinel;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * CodeSentinel AI — Main Application Entry Point.
 *
 * An AI-powered secure code review system that integrates with
 * GitHub Pull Requests and automatically detects security vulnerabilities
 * using static analysis, agentic AI (LangGraph), and RAG-augmented OWASP guidelines.
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class CodeSentinelApplication {

    public static void main(String[] args) {
        SpringApplication.run(CodeSentinelApplication.class, args);
    }
}
