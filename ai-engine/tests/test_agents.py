"""Tests for the LangGraph security review workflow."""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.agents.code_analyzer import code_analyzer
from app.agents.security_agent import security_agent, _fallback_mapping
from app.agents.fix_generator import fix_generator, _fallback_fixes
from app.agents.explanation_agent import explanation_agent
from app.agents.reviewer import reviewer, _fallback_consolidation


class TestCodeAnalyzer:
    """Tests for the Code Analyzer agent."""

    def test_analyze_with_sql_injection(self):
        state = {
            "code_diffs": [
                {
                    "filename": "UserService.java",
                    "patch": '+String query = "SELECT * FROM users WHERE name = \'" + name + "\'";',
                    "status": "modified",
                    "language": "java",
                }
            ]
        }
        result = code_analyzer(state)
        assert "analysis_results" in result
        assert isinstance(result["analysis_results"], list)

    def test_analyze_empty_diffs(self):
        state = {"code_diffs": []}
        result = code_analyzer(state)
        assert result["analysis_results"] == []

    def test_analyze_without_diffs(self):
        state = {}
        result = code_analyzer(state)
        assert result["analysis_results"] == []


class TestSecurityAgent:
    """Tests for the Security Agent."""

    def test_fallback_mapping_sql_injection(self):
        findings = [{"vulnerability": "SQL Injection", "severity": "HIGH", "file": "test.java"}]
        result = _fallback_mapping(findings)
        assert len(result) == 1
        assert result[0]["owasp"] == "A03:2021 Injection"

    def test_fallback_mapping_hardcoded_secret(self):
        findings = [{"vulnerability": "Hardcoded Secret", "severity": "CRITICAL", "file": "config.py"}]
        result = _fallback_mapping(findings)
        assert result[0]["owasp"] == "A02:2021 Cryptographic Failures"

    def test_security_agent_empty_input(self):
        state = {"analysis_results": []}
        result = security_agent(state)
        assert result["security_findings"] == []


class TestFixGenerator:
    """Tests for the Fix Generator agent."""

    def test_fallback_fixes(self):
        findings = [
            {"vulnerability": "SQL Injection", "file": "test.java"},
            {"vulnerability": "Hardcoded Secret", "file": "config.py"},
        ]
        result = _fallback_fixes(findings)
        assert len(result) == 2
        assert "parameterized" in result[0]["fix"].lower()
        assert "environment" in result[1]["fix"].lower()

    def test_fix_generator_empty(self):
        state = {"security_findings": []}
        result = fix_generator(state)
        assert result["fix_suggestions"] == []


class TestExplanationAgent:
    """Tests for the Explanation Agent."""

    def test_explanation_empty(self):
        state = {"security_findings": [], "fix_suggestions": []}
        result = explanation_agent(state)
        assert result["explanations"] == []


class TestReviewer:
    """Tests for the Reviewer agent."""

    def test_fallback_consolidation(self):
        findings = [
            {"vulnerability": "SQL Injection", "severity": "HIGH", "file": "a.java", "owasp": "A03:2021 Injection"},
            {"vulnerability": "SQL Injection", "severity": "HIGH", "file": "a.java", "owasp": "A03:2021 Injection"},  # duplicate
            {"vulnerability": "XSS", "severity": "MEDIUM", "file": "b.js", "owasp": "A03:2021 Injection"},
        ]
        fixes = [{"vulnerability": "SQL Injection", "fix": "Use PreparedStatement"}]
        explanations = [{"vulnerability": "SQL Injection", "explanation": "SQL injection allows..."}]

        result = _fallback_consolidation(findings, fixes, explanations)

        # Should deduplicate: 2 unique findings
        assert len(result) == 2

    def test_reviewer_empty(self):
        state = {"security_findings": [], "fix_suggestions": [], "explanations": []}
        result = reviewer(state)
        assert result["final_review"] == []

    def test_reviewer_sorts_by_severity(self):
        state = {
            "security_findings": [
                {"vulnerability": "Low risk", "severity": "LOW", "file": "a.java", "owasp": "A04:2021"},
                {"vulnerability": "Critical risk", "severity": "CRITICAL", "file": "b.java", "owasp": "A03:2021"},
            ],
            "fix_suggestions": [],
            "explanations": [],
        }
        result = reviewer(state)
        reviews = result["final_review"]
        if len(reviews) >= 2:
            assert reviews[0]["severity"] == "CRITICAL"
