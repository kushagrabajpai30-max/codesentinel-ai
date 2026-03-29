"""
Reviewer Agent — Final node that consolidates all findings into structured output.

Removes false positives, deduplicates, prioritizes by severity, and produces
the final VulnerabilityFinding list.
"""

from __future__ import annotations

import json
import logging

from app.llm.client import get_llm_client
from app.models.state import ReviewState

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """You are the final security review gatekeeper. Review all findings from the security analysis pipeline and produce a consolidated, deduplicated, prioritized list of confirmed vulnerabilities.

Your responsibilities:
1. Remove obvious false positives
2. Deduplicate similar findings
3. Merge fix suggestions and explanations into each finding
4. Prioritize by severity (CRITICAL > HIGH > MEDIUM > LOW)
5. Ensure each finding has all required fields

SECURITY FINDINGS:
{security_findings}

FIX SUGGESTIONS:
{fix_suggestions}

EXPLANATIONS:
{explanations}

Respond ONLY with a JSON array of final findings. Each must have ALL these fields:
- "file": filename
- "line_number": line number if known, otherwise null
- "vulnerability": vulnerability type name
- "severity": one of LOW, MEDIUM, HIGH, CRITICAL
- "issue": description of the security issue
- "fix": actionable fix instruction
- "explanation": developer-friendly explanation
- "owasp": OWASP category identifier (e.g., "A03:2021 Injection")

Order by severity (CRITICAL first, then HIGH, MEDIUM, LOW).
Return an empty array [] if no confirmed vulnerabilities.
"""


def reviewer(state: ReviewState) -> dict:
    """
    LangGraph node: Final reviewer that consolidates all findings.

    Reads: state["security_findings"], state["fix_suggestions"], state["explanations"]
    Writes: state["final_review"]
    """
    security_findings = state.get("security_findings", [])
    fix_suggestions = state.get("fix_suggestions", [])
    explanations = state.get("explanations", [])

    if not security_findings:
        logger.info("Reviewer: No findings to review")
        return {"final_review": []}

    llm = get_llm_client()
    prompt = PROMPT_TEMPLATE.format(
        security_findings=json.dumps(security_findings, indent=2),
        fix_suggestions=json.dumps(fix_suggestions, indent=2),
        explanations=json.dumps(explanations, indent=2),
    )

    logger.info(f"Reviewer: Consolidating {len(security_findings)} findings")
    response = llm.invoke(prompt)

    try:
        content = response.content if hasattr(response, "content") else str(response)
        final = _parse_json_response(content)
        logger.info(f"Reviewer: Finalized {len(final)} confirmed vulnerabilities")
    except Exception as e:
        logger.error(f"Reviewer: Failed to parse response: {e}")
        final = _fallback_consolidation(security_findings, fix_suggestions, explanations)

    # Sort by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    final.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 2))

    return {"final_review": final}


def _fallback_consolidation(
    findings: list[dict],
    fixes: list[dict],
    explanations: list[dict],
) -> list[dict]:
    """Consolidate findings using simple merging when LLM fails."""
    # Index fixes and explanations by vulnerability name
    fix_map = {}
    for fix in fixes:
        key = fix.get("vulnerability", "").lower()
        fix_map[key] = fix

    expl_map = {}
    for expl in explanations:
        key = expl.get("vulnerability", "").lower()
        expl_map[key] = expl

    # Deduplicate by (file, vulnerability) tuple
    seen = set()
    consolidated = []

    for finding in findings:
        key = (finding.get("file", ""), finding.get("vulnerability", ""))
        if key in seen:
            continue
        seen.add(key)

        vuln_lower = finding.get("vulnerability", "").lower()
        fix_info = fix_map.get(vuln_lower, {})
        expl_info = expl_map.get(vuln_lower, {})

        consolidated.append({
            "file": finding.get("file", "unknown"),
            "line_number": finding.get("line_number"),
            "vulnerability": finding.get("vulnerability", "Unknown"),
            "severity": finding.get("severity", "MEDIUM"),
            "issue": finding.get("issue", finding.get("description", "Security issue detected")),
            "fix": fix_info.get("fix", finding.get("fix", "Apply secure coding practices")),
            "explanation": expl_info.get("explanation", "Review this code for potential security issues"),
            "owasp": finding.get("owasp", "A04:2021 Insecure Design"),
        })

    return consolidated


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
