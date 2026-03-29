"""
Code Analyzer Agent — First node in the LangGraph pipeline.

Examines code diffs and identifies potentially vulnerable patterns.
"""

from __future__ import annotations

import json
import logging

from app.llm.client import get_llm_client
from app.models.state import ReviewState

logger = logging.getLogger(__name__)

PROMPT_TEMPLATE = """You are an expert code security analyst. Analyze the following code changes from a Pull Request and identify any potential security vulnerabilities.

For each vulnerability found, provide:
1. The file where it was found
2. A brief description of the vulnerability type
3. The severity (LOW, MEDIUM, HIGH, CRITICAL)
4. A description of the issue

Respond ONLY with a JSON array of findings. Each finding should have these fields:
- "file": filename
- "vulnerability": type name
- "severity": level
- "description": what the issue is
- "line_context": the relevant code snippet

If no vulnerabilities are found, return an empty array: []

CODE CHANGES:
{code_diffs}
"""


def code_analyzer(state: ReviewState) -> dict:
    """
    LangGraph node: Analyzes code diffs for potential security vulnerabilities.

    Reads: state["code_diffs"]
    Writes: state["analysis_results"]
    """
    code_diffs = state.get("code_diffs", [])

    if not code_diffs:
        logger.warning("No code diffs provided to analyzer")
        return {"analysis_results": []}

    # Format diffs for the prompt
    diffs_text = _format_diffs(code_diffs)

    # Call LLM
    llm = get_llm_client()
    prompt = PROMPT_TEMPLATE.format(code_diffs=diffs_text)

    logger.info(f"Code Analyzer: Analyzing {len(code_diffs)} files")
    response = llm.invoke(prompt)

    # Parse response
    try:
        content = response.content if hasattr(response, "content") else str(response)
        # Try to extract JSON from the response
        findings = _parse_json_response(content)
        logger.info(f"Code Analyzer: Found {len(findings)} potential issues")
    except Exception as e:
        logger.error(f"Code Analyzer: Failed to parse LLM response: {e}")
        findings = []

    return {"analysis_results": findings}


def _format_diffs(diffs: list[dict]) -> str:
    """Format file diffs into a readable string for the LLM prompt."""
    parts = []
    for diff in diffs:
        parts.append(f"--- File: {diff.get('filename', 'unknown')} ({diff.get('language', 'unknown')}) ---")
        parts.append(f"Status: {diff.get('status', 'modified')}")
        parts.append(diff.get("patch", ""))
        parts.append("")
    return "\n".join(parts)


def _parse_json_response(content: str) -> list[dict]:
    """Extract and parse JSON from LLM response, handling markdown code blocks."""
    content = content.strip()

    # Remove markdown code block if present
    if content.startswith("```"):
        lines = content.split("\n")
        content = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    try:
        result = json.loads(content)
        return result if isinstance(result, list) else [result]
    except json.JSONDecodeError:
        # Try to find JSON array in the response
        start = content.find("[")
        end = content.rfind("]")
        if start != -1 and end != -1:
            try:
                return json.loads(content[start : end + 1])
            except json.JSONDecodeError:
                pass
        return []
