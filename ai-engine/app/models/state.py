"""
Shared state definition for the LangGraph security review workflow.

The ReviewState flows through all agents in the graph, with each agent
reading from and writing to specific keys.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TypedDict


class FileDiff(TypedDict):
    """A single file diff from a pull request."""
    filename: str
    patch: str
    status: str  # added, modified, removed
    language: str


class VulnerabilityFinding(TypedDict, total=False):
    """A single vulnerability finding produced by the agents."""
    file: str
    line_number: Optional[int]
    vulnerability: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    issue: str
    fix: str
    explanation: str
    owasp: str


class ReviewState(TypedDict, total=False):
    """
    Shared state flowing through the LangGraph security review workflow.

    START → code_analyzer → security_agent → fix_generator → explanation_agent → reviewer → END
    """
    # Input
    code_diffs: List[FileDiff]

    # Intermediate state updated by each agent
    analysis_results: List[Dict]        # Code Analyzer output
    security_findings: List[Dict]       # Security Agent output (with OWASP mapping)
    fix_suggestions: List[Dict]         # Fix Generator output
    explanations: List[Dict]            # Explanation Agent output

    # RAG context retrieved from OWASP knowledge base
    rag_context: List[str]

    # Final output
    final_review: List[VulnerabilityFinding]
