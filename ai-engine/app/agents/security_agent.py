"""
Security Agent — Maps findings to OWASP Top 10 and assigns severity.

Uses RAG to retrieve relevant OWASP guidelines for enhanced analysis.
"""

from __future__ import annotations

import json
import logging

from app.llm.client import get_llm_client
from app.models.state import ReviewState

logger = logging.getLogger(__name__)

# OWASP Top 10 (2021) quick reference for the LLM
OWASP_REFERENCE = """
OWASP Top 10 (2021):
A01:2021 - Broken Access Control
A02:2021 - Cryptographic Failures
A03:2021 - Injection (SQL, OS Command, XSS, etc.)
A04:2021 - Insecure Design
A05:2021 - Security Misconfiguration
A06:2021 - Vulnerable and Outdated Components
A07:2021 - Identification and Authentication Failures
A08:2021 - Software and Data Integrity Failures
A09:2021 - Security Logging and Monitoring Failures
A10:2021 - Server-Side Request Forgery (SSRF)
"""

PROMPT_TEMPLATE = """You are a cybersecurity expert specializing in OWASP guidelines. Given the following code analysis findings and OWASP reference context, provide a detailed security assessment.

For each finding:
1. Map it to the most relevant OWASP Top 10 category
2. Confirm or adjust the severity level (LOW, MEDIUM, HIGH, CRITICAL)
3. Provide the OWASP identifier (e.g., "A03:2021 Injection")

OWASP REFERENCE:
{owasp_reference}

ADDITIONAL OWASP CONTEXT (from knowledge base):
{rag_context}

CODE ANALYSIS FINDINGS:
{analysis_results}

Respond ONLY with a JSON array. Each item should have:
- "file": filename
- "vulnerability": type name
- "severity": adjusted severity
- "owasp": OWASP identifier and name (e.g., "A03:2021 Injection")
- "issue": detailed description of the security issue
- "confidence": HIGH, MEDIUM, or LOW

If no security issues are confirmed, return an empty array: []
"""


def security_agent(state: ReviewState) -> dict:
    """
    LangGraph node: Maps analysis results to OWASP categories and assigns severity.

    Reads: state["analysis_results"], state["rag_context"]
    Writes: state["security_findings"]
    """
    analysis_results = state.get("analysis_results", [])
    rag_context = state.get("rag_context", [])

    if not analysis_results:
        logger.info("Security Agent: No analysis results to process")
        return {"security_findings": []}

    # Format RAG context
    rag_text = "\n\n".join(rag_context) if rag_context else "No additional context available."

    # Call LLM
    llm = get_llm_client()
    prompt = PROMPT_TEMPLATE.format(
        owasp_reference=OWASP_REFERENCE,
        rag_context=rag_text,
        analysis_results=json.dumps(analysis_results, indent=2),
    )

    logger.info(f"Security Agent: Processing {len(analysis_results)} findings with OWASP mapping")
    response = llm.invoke(prompt)

    # Parse response
    try:
        content = response.content if hasattr(response, "content") else str(response)
        findings = _parse_json_response(content)
        logger.info(f"Security Agent: Produced {len(findings)} security findings")
    except Exception as e:
        logger.error(f"Security Agent: Failed to parse response: {e}")
        # Fallback: use analysis results with default OWASP mapping
        findings = _fallback_mapping(analysis_results)

    return {"security_findings": findings}


def _fallback_mapping(analysis_results: list[dict]) -> list[dict]:
    """Map analysis results to OWASP categories using simple keyword matching."""
    owasp_map = {
        "sql injection": "A03:2021 Injection",
        "xss": "A03:2021 Injection",
        "cross-site scripting": "A03:2021 Injection",
        "command injection": "A03:2021 Injection",
        "hardcoded secret": "A02:2021 Cryptographic Failures",
        "hardcoded credential": "A02:2021 Cryptographic Failures",
        "hardcoded password": "A02:2021 Cryptographic Failures",
        "insecure deserialization": "A08:2021 Software and Data Integrity Failures",
        "path traversal": "A01:2021 Broken Access Control",
        "insecure cookie": "A05:2021 Security Misconfiguration",
        "weak cryptography": "A02:2021 Cryptographic Failures",
        "mass assignment": "A01:2021 Broken Access Control",
    }

    findings = []
    for result in analysis_results:
        vuln = result.get("vulnerability", "").lower()
        owasp = "A04:2021 Insecure Design"  # default
        for keyword, mapping in owasp_map.items():
            if keyword in vuln:
                owasp = mapping
                break

        findings.append({
            **result,
            "owasp": owasp,
            "confidence": "MEDIUM",
        })

    return findings


def _parse_json_response(content: str) -> list[dict]:
    """Extract and parse JSON from LLM response."""
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    try:
        result = json.loads(content)
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
