package com.codesentinel.service;

import com.codesentinel.model.Severity;
import com.codesentinel.model.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class StaticAnalysisServiceTest {

    private StaticAnalysisService analysisService;

    @BeforeEach
    void setUp() {
        analysisService = new StaticAnalysisService();
    }

    @Test
    @DisplayName("Should detect SQL injection via string concatenation")
    void detectSqlInjection() {
        List<Map<String, String>> diffs = List.of(
                createDiff("UserDao.java", """
                        @@ -1,5 +1,5 @@
                        +String query = "SELECT * FROM users WHERE id = '" + userId + "'";
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().equals("SQL Injection") &&
                v.getSeverity() == Severity.HIGH);
    }

    @Test
    @DisplayName("Should detect hardcoded secrets")
    void detectHardcodedSecrets() {
        List<Map<String, String>> diffs = List.of(
                createDiff("Config.java", """
                        @@ -1,3 +1,3 @@
                        +private static final String API_KEY = "sk-proj-abc123def456ghi789";
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().equals("Hardcoded Secret") &&
                v.getSeverity() == Severity.CRITICAL);
    }

    @Test
    @DisplayName("Should detect XSS via innerHTML")
    void detectXss() {
        List<Map<String, String>> diffs = List.of(
                createDiff("app.js", """
                        @@ -1,3 +1,3 @@
                        +document.getElementById('output').innerHTML = userInput;
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().contains("XSS") &&
                v.getSeverity() == Severity.HIGH);
    }

    @Test
    @DisplayName("Should detect command injection via os.system")
    void detectCommandInjection() {
        List<Map<String, String>> diffs = List.of(
                createDiff("script.py", """
                        @@ -1,3 +1,3 @@
                        +result = os.system("grep " + user_input + " /var/log/app.log")
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().equals("Command Injection") &&
                v.getSeverity() == Severity.CRITICAL);
    }

    @Test
    @DisplayName("Should detect insecure deserialization")
    void detectInsecureDeserialization() {
        List<Map<String, String>> diffs = List.of(
                createDiff("utils.py", """
                        @@ -1,3 +1,3 @@
                        +data = pickle.loads(data_bytes)
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().equals("Insecure Deserialization"));
    }

    @Test
    @DisplayName("Should detect hardcoded connection strings")
    void detectHardcodedConnectionString() {
        List<Map<String, String>> diffs = List.of(
                createDiff("config.py", """
                        @@ -1,3 +1,3 @@
                        +DATABASE_URL = "postgresql://admin:password123@prod-db:5432/mydb"
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().equals("Hardcoded Connection String"));
    }

    @Test
    @DisplayName("Should detect insecure cookie configuration")
    void detectInsecureCookie() {
        List<Map<String, String>> diffs = List.of(
                createDiff("auth.js", """
                        @@ -1,3 +1,3 @@
                        +res.cookie('session', token, { httpOnly: false, secure: false });
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isNotEmpty();
        assertThat(result).anyMatch(v ->
                v.getVulnerability().equals("Insecure Cookie Configuration"));
    }

    @Test
    @DisplayName("Should return empty list for safe code")
    void safeCode() {
        List<Map<String, String>> diffs = List.of(
                createDiff("SafeService.java", """
                        @@ -1,3 +1,3 @@
                        +public String greet(String name) {
                        +    return "Hello, " + name;
                        +}
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("Should detect multiple vulnerabilities in same file")
    void detectMultipleVulnerabilities() {
        List<Map<String, String>> diffs = List.of(
                createDiff("UserService.java", """
                        @@ -1,5 +1,5 @@
                        +String query = "SELECT * FROM users WHERE name = '" + name + "'";
                        +private static final String API_KEY = "sk-proj-abc123def456ghi789jkl";
                        """)
        );

        List<Vulnerability> result = analysisService.analyze(1L, diffs);
        assertThat(result.size()).isGreaterThanOrEqualTo(2);
    }

    private Map<String, String> createDiff(String filename, String patch) {
        Map<String, String> diff = new HashMap<>();
        diff.put("filename", filename);
        diff.put("patch", patch);
        diff.put("status", "modified");
        return diff;
    }
}
