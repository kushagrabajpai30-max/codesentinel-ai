package com.codesentinel.service;

import com.codesentinel.model.DetectionSource;
import com.codesentinel.model.Severity;
import com.codesentinel.model.Vulnerability;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rule-based static analysis engine that detects common security vulnerabilities
 * using regex pattern matching on code diffs.
 */
@Service
@Slf4j
public class StaticAnalysisService {

    /**
     * Holds a single detection rule definition.
     */
    private record SecurityRule(
            String name,
            Pattern pattern,
            Severity severity,
            String issue,
            String fix,
            String owaspMapping,
            String... applicableLanguages
    ) {}

    private final List<SecurityRule> rules = initRules();

    /**
     * Analyzes a list of file diffs and returns detected vulnerabilities.
     */
    public List<Vulnerability> analyze(Long prEventId, List<Map<String, String>> diffs) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (Map<String, String> diff : diffs) {
            String filename = diff.get("filename");
            String patch = diff.get("patch");

            if (patch == null || patch.isBlank()) continue;

            String language = detectLanguage(filename);
            String[] lines = patch.split("\n");

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                // Only analyze added lines (lines starting with +)
                if (!line.startsWith("+") || line.startsWith("+++") || line.startsWith("@@")) {
                    continue;
                }

                String codeLine = line.substring(1).trim();
                if (codeLine.isEmpty()) continue;

                for (SecurityRule rule : rules) {
                    // Check language applicability
                    if (rule.applicableLanguages.length > 0) {
                        boolean applicable = false;
                        for (String lang : rule.applicableLanguages) {
                            if (lang.equals(language) || lang.equals("all")) {
                                applicable = true;
                                break;
                            }
                        }
                        if (!applicable) continue;
                    }

                    Matcher matcher = rule.pattern.matcher(codeLine);
                    if (matcher.find()) {
                        vulnerabilities.add(Vulnerability.builder()
                                .prEventId(prEventId)
                                .file(filename)
                                .lineNumber(i + 1)
                                .vulnerability(rule.name)
                                .severity(rule.severity)
                                .issue(rule.issue)
                                .fix(rule.fix)
                                .explanation("Detected by static analysis rule: " + rule.name)
                                .owaspMapping(rule.owaspMapping)
                                .source(DetectionSource.STATIC)
                                .build());

                        log.debug("  [STATIC] {} in {} at line {}: {}",
                                rule.name, filename, i + 1, codeLine);
                    }
                }
            }
        }

        log.info("Static analysis complete: {} vulnerabilities found", vulnerabilities.size());
        return vulnerabilities;
    }

    /**
     * Initializes the rule set for static analysis.
     */
    private List<SecurityRule> initRules() {
        List<SecurityRule> ruleSet = new ArrayList<>();

        // ── SQL Injection ────────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "SQL Injection",
                Pattern.compile(
                        "(?i)(\"\\s*SELECT|\"\\s*INSERT|\"\\s*UPDATE|\"\\s*DELETE|\"\\s*DROP).*\\+\\s*\\w+",
                        Pattern.CASE_INSENSITIVE),
                Severity.HIGH,
                "User input directly concatenated into SQL query string",
                "Use PreparedStatement or parameterized queries instead of string concatenation",
                "A03:2021 Injection",
                "java", "python", "php", "all"
        ));

        // ── XSS (Cross-Site Scripting) ───────────────────────────────
        ruleSet.add(new SecurityRule(
                "Cross-Site Scripting (XSS)",
                Pattern.compile(
                        "(?i)(innerHTML\\s*=|document\\.write\\(|\\$\\(.*\\)\\.html\\(|<\\w+[^>]*>.*\\+\\s*\\w+)"),
                Severity.HIGH,
                "User input rendered directly in HTML without sanitization",
                "Use textContent instead of innerHTML, or sanitize input with DOMPurify",
                "A03:2021 Injection",
                "javascript", "typescript", "java", "all"
        ));

        // ── Hardcoded Secrets ────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Hardcoded Secret",
                Pattern.compile(
                        "(?i)(api[_-]?key|secret[_-]?key|password|passwd|token|aws[_-]?secret|private[_-]?key)\\s*=\\s*[\"'][^\"']{8,}[\"']"),
                Severity.CRITICAL,
                "Sensitive credential or API key hardcoded in source code",
                "Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)",
                "A02:2021 Cryptographic Failures",
                "all"
        ));

        // ── Hardcoded Connection Strings ─────────────────────────────
        ruleSet.add(new SecurityRule(
                "Hardcoded Connection String",
                Pattern.compile(
                        "(?i)(jdbc:|postgresql://|mysql://|mongodb://|redis://).*:.*@"),
                Severity.HIGH,
                "Database connection string with credentials hardcoded in source",
                "Use environment variables or a connection pool with externalized configuration",
                "A02:2021 Cryptographic Failures",
                "all"
        ));

        // ── Command Injection ────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Command Injection",
                Pattern.compile(
                        "(?i)(Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder|os\\.system|subprocess\\.(call|run|Popen)|exec\\(|eval\\()"),
                Severity.CRITICAL,
                "User input potentially passed to OS command execution",
                "Avoid using shell commands with user input; use parameterized APIs or allowlists",
                "A03:2021 Injection",
                "all"
        ));

        // ── Insecure Deserialization ─────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Insecure Deserialization",
                Pattern.compile(
                        "(?i)(pickle\\.loads?|ObjectInputStream|yaml\\.load\\((?!.*Loader)|readObject\\(|unserialize\\()"),
                Severity.HIGH,
                "Deserializing untrusted data can lead to remote code execution",
                "Use safe deserialization methods (e.g., yaml.safe_load, JSON instead of pickle)",
                "A08:2021 Software and Data Integrity Failures",
                "all"
        ));

        // ── Path Traversal ───────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Path Traversal",
                Pattern.compile(
                        "(?i)(open\\(|File\\(|new File|readFile|readFileSync).*\\+\\s*\\w+"),
                Severity.HIGH,
                "File path constructed with user input without validation",
                "Validate and sanitize file paths; use allowlists and Path.normalize()",
                "A01:2021 Broken Access Control",
                "all"
        ));

        // ── Insecure Cookie ──────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Insecure Cookie Configuration",
                Pattern.compile(
                        "(?i)(httpOnly\\s*:\\s*false|secure\\s*:\\s*false|sameSite\\s*:\\s*[\"']none[\"'])"),
                Severity.MEDIUM,
                "Cookie set without secure flags (httpOnly, secure, or sameSite)",
                "Set httpOnly: true, secure: true, and sameSite: 'strict' or 'lax'",
                "A05:2021 Security Misconfiguration",
                "javascript", "typescript", "all"
        ));

        // ── Weak Cryptography ────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Weak Cryptography",
                Pattern.compile(
                        "(?i)(MD5|SHA1|DES|RC4|Math\\.random\\(\\)|java\\.util\\.Random)"),
                Severity.MEDIUM,
                "Use of weak or broken cryptographic algorithm",
                "Use SHA-256+ for hashing, AES-256 for encryption, SecureRandom for randomness",
                "A02:2021 Cryptographic Failures",
                "all"
        ));

        // ── Mass Assignment ──────────────────────────────────────────
        ruleSet.add(new SecurityRule(
                "Mass Assignment",
                Pattern.compile(
                        "(?i)(\\$set\\s*:\\s*req\\.body|Object\\.assign\\(.*req\\.body|\\{\\s*\\.\\.\\.req\\.body)"),
                Severity.MEDIUM,
                "Directly assigning request body to database object without filtering",
                "Explicitly whitelist allowed fields instead of assigning entire request body",
                "A01:2021 Broken Access Control",
                "javascript", "typescript", "all"
        ));

        return ruleSet;
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
        return "unknown";
    }
}
