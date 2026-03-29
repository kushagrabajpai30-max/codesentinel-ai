package com.codesentinel.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Mock GitHub API service that returns sample PR diffs for testing.
 * In production, this would call the real GitHub REST API using the configured token.
 */
@Service
@Slf4j
public class GitHubApiService {

    /**
     * Fetches the file diffs for a pull request.
     * Returns a list of maps, each containing "filename", "patch", and "status".
     *
     * Currently returns mock data for demo purposes.
     */
    public List<Map<String, String>> fetchPullRequestDiffs(String repoFullName, Integer prNumber) {
        log.info("Fetching diffs for {}#{} (mock)", repoFullName, prNumber);

        List<Map<String, String>> diffs = new ArrayList<>();

        // ── Sample Vulnerable Java File ──────────────────────────────
        diffs.add(createDiff("src/main/java/com/example/UserService.java", "modified",
                """
                @@ -15,6 +15,20 @@ public class UserService {
                +    // Database query method
                +    public User findUser(String username) {
                +        String query = "SELECT * FROM users WHERE username = '" + username + "'";
                +        return jdbcTemplate.queryForObject(query, new UserRowMapper());
                +    }
                +
                +    // API key stored in code
                +    private static final String API_KEY = "sk-proj-abc123def456ghi789";
                +    private static final String DB_PASSWORD = "admin123";
                +
                +    // Process user input for display
                +    public String renderUserProfile(String userInput) {
                +        return "<div class='profile'>" + userInput + "</div>";
                +    }
                """));

        // ── Sample Vulnerable Python File ────────────────────────────
        diffs.add(createDiff("src/scripts/data_processor.py", "added",
                """
                @@ -0,0 +1,30 @@
                +import os
                +import subprocess
                +import pickle
                +import yaml
                +
                +def process_file(user_path):
                +    # Path traversal vulnerability
                +    file_path = "/data/uploads/" + user_path
                +    with open(file_path, 'r') as f:
                +        return f.read()
                +
                +def run_command(user_input):
                +    # Command injection vulnerability
                +    result = os.system("grep " + user_input + " /var/log/app.log")
                +    return result
                +
                +def load_data(data_bytes):
                +    # Insecure deserialization
                +    return pickle.loads(data_bytes)
                +
                +def parse_config(config_str):
                +    # Unsafe YAML loading
                +    return yaml.load(config_str)
                +
                +AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"
                +DATABASE_URL = "postgresql://admin:password123@prod-db:5432/mydb"
                """));

        // ── Sample Vulnerable JavaScript File ────────────────────────
        diffs.add(createDiff("src/frontend/auth.js", "modified",
                """
                @@ -10,5 +10,25 @@
                +function authenticateUser(req, res) {
                +    const token = req.query.token;
                +    // No CSRF protection
                +    // Token passed in URL query parameter
                +
                +    const userId = req.params.id;
                +    // Mass assignment vulnerability
                +    db.users.update({ _id: userId }, { $set: req.body });
                +
                +    // Insecure cookie
                +    res.cookie('session', token, { httpOnly: false, secure: false });
                +
                +    // eval usage
                +    const config = eval('(' + req.body.config + ')');
                +
                +    // DOM XSS
                +    document.getElementById('output').innerHTML = req.query.message;
                +}
                """));

        log.info("Returned {} mock file diffs", diffs.size());
        return diffs;
    }

    private Map<String, String> createDiff(String filename, String status, String patch) {
        Map<String, String> diff = new HashMap<>();
        diff.put("filename", filename);
        diff.put("status", status);
        diff.put("patch", patch);
        return diff;
    }
}
