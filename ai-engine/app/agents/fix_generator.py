"""
Fix Generator Agent — Generates concrete fix suggestions for each vulnerability.
"""

from __future__ import annotations

import json
import logging

from app.llm.client import get_llm_client
from app.models.state import ReviewState

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """You are a senior software engineer specializing in secure coding. For each security vulnerability below, provide a concrete, actionable fix.

For each finding, provide:
1. The recommended fix as a clear instruction
2. A corrected code snippet (if applicable)
3. Best practice recommendation

SECURITY FINDINGS:
{security_findings}

Respond ONLY with a JSON array. Each item should have:
- "file": filename
- "vulnerability": type name
- "fix": clear fix instruction
- "code_fix": corrected code snippet (if applicable, otherwise null)
- "best_practice": recommended best practice

Return an empty array [] if no findings to process.
"""


def fix_generator(state: ReviewState) -> dict:
    """
    LangGraph node: Generates fix suggestions for each security finding.

    Reads: state["security_findings"]
    Writes: state["fix_suggestions"]
    """
    security_findings = state.get("security_findings", [])

    if not security_findings:
        logger.info("Fix Generator: No security findings to process")
        return {"fix_suggestions": []}

    llm = get_llm_client()
    prompt = PROMPT_TEMPLATE.format(
        security_findings=json.dumps(security_findings, indent=2)
    )

    logger.info(f"Fix Generator: Generating fixes for {len(security_findings)} findings")
    response = llm.invoke(prompt)

    try:
        content = response.content if hasattr(response, "content") else str(response)
        suggestions = _parse_json_response(content)
        logger.info(f"Fix Generator: Produced {len(suggestions)} fix suggestions")
    except Exception as e:
        logger.error(f"Fix Generator: Failed to parse response: {e}")
        suggestions = _fallback_fixes(security_findings)

    return {"fix_suggestions": suggestions}


def _fallback_fixes(findings: list[dict]) -> list[dict]:
    """Generate fallback fix suggestions based on vulnerability type."""
    fix_map = {
        "sql injection": {
            "fix": "Use parameterized queries or PreparedStatement instead of string concatenation",
            "best_practice": "Never concatenate user input into SQL queries",
        },
        "xss": {
            "fix": "Sanitize output using DOMPurify or use textContent instead of innerHTML",
            "best_practice": "Always encode/escape output based on context (HTML, JS, URL)",
        },
        "cross-site scripting": {
            "fix": "Use output encoding and Content-Security-Policy headers",
            "best_practice": "Implement CSP headers and sanitize all user-generated content",
        },
        "hardcoded secret": {
            "fix": "Move credentials to environment variables or a secrets manager",
            "best_practice": "Use AWS Secrets Manager, HashiCorp Vault, or similar tools",
        },
        "command injection": {
            "fix": "Use parameterized APIs instead of shell commands with user input",
            "best_practice": "Avoid os.system/exec; use subprocess with shell=False and argument lists",
        },
        "insecure deserialization": {
            "fix": "Use safe serialization formats like JSON instead of pickle/ObjectInputStream",
            "best_practice": "Never deserialize untrusted data; validate and sanitize input",
        },
        "path traversal": {
            "fix": "Validate and sanitize file paths; use allowlists and canonical path checks",
            "best_practice": "Use Path.resolve() and check against a base directory",
        },
    }

    suggestions = []
    for finding in findings:
        vuln = finding.get("vulnerability", "").lower()
        fix_info = {"fix": "Review and apply secure coding practices", "best_practice": "Follow OWASP guidelines"}

        for key, value in fix_map.items():
            if key in vuln:
                fix_info = value
                break

        suggestions.append({
            "file": finding.get("file", "unknown"),
            "vulnerability": finding.get("vulnerability", "Unknown"),
            **fix_info,
            "code_fix": None,
        })

    return suggestions


def _parse_json_response(content: str) -> list[dict]:
    """Extract and parse JSON from LLM response."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    try:
        result = json.loads(content)
        if isinstance(result, dict) and "fixes" in result:
            return result["fixes"]
        return result if isinstance(result, list) else [result]
    except json.JSONDecodeError:
        start = content.find("[")
        end = content.rfind("]")
        if start != -1 and end != -1:
            try:
                return json.loads(content[start : end + 1])
            except json.JSONDecodeError:
                pass
        return []
