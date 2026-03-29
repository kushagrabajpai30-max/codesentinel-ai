"""
LangGraph Security Review Workflow — Orchestrates the multi-agent pipeline.

Pipeline: START → rag_enrichment → code_analyzer → security_agent → fix_generator → explanation_agent → reviewer → END

Compatible with LangGraph >=0.2.0 (uses both old and new API patterns).
"""

from __future__ import annotations

import logging
from typing import Any, List, Dict, Optional

from app.agents.code_analyzer import code_analyzer
from app.agents.security_agent import security_agent
from app.agents.fix_generator import fix_generator
from app.agents.explanation_agent import explanation_agent
from app.agents.reviewer import reviewer
from app.models.state import ReviewState

logger = logging.getLogger(__name__)

# Optional RAG import — gracefully handle if not available
_rag_retriever = None


def _get_rag_retriever():
    """Lazily load the RAG retriever."""
    global _rag_retriever
    if _rag_retriever is None:
        try:
            from app.rag.vector_store import get_retriever
            _rag_retriever = get_retriever()
            logger.info("RAG retriever loaded successfully")
        except Exception as e:
            logger.warning(f"RAG retriever not available: {e}")
            _rag_retriever = None
    return _rag_retriever


def rag_enrichment(state: ReviewState) -> dict:
    """
    Pre-processing step: Retrieves relevant OWASP context using RAG.

    Reads: state["code_diffs"]
    Writes: state["rag_context"]
    """
    code_diffs = state.get("code_diffs", [])
    retriever = _get_rag_retriever()

    if not retriever or not code_diffs:
        return {"rag_context": []}

    # Build a query from the code diffs
    query_parts = []
    for diff in code_diffs:
        patch = diff.get("patch", "")
        if "SELECT" in patch or "query" in patch:
            query_parts.append("SQL injection prevention")
        if "innerHTML" in patch or "document.write" in patch:
            query_parts.append("XSS prevention")
        if "API_KEY" in patch or "password" in patch or "secret" in patch:
            query_parts.append("credential management")
        if "os.system" in patch or "subprocess" in patch or "eval(" in patch:
            query_parts.append("command injection prevention")
        if "pickle" in patch:
            query_parts.append("insecure deserialization")

    if not query_parts:
        query_parts.append("secure coding best practices")

    query = " ".join(set(query_parts))
    logger.info(f"RAG query: {query}")

    try:
        docs = retriever.invoke(query)
        context = [doc.page_content for doc in docs[:5]]
        logger.info(f"RAG retrieved {len(context)} relevant documents")
        return {"rag_context": context}
    except Exception as e:
        logger.warning(f"RAG retrieval failed: {e}")
        return {"rag_context": []}


def build_review_graph() -> Any:
    """
    Builds and compiles the LangGraph security review workflow.

    Returns a compiled graph that can be invoked with:
        result = graph.invoke({"code_diffs": [...]})
    """
    from langgraph.graph import StateGraph, END

    # Try new API first (LangGraph >= 0.2.x with START constant)
    try:
        from langgraph.graph import START
        _has_start = True
    except ImportError:
        _has_start = False

    graph = StateGraph(ReviewState)

    # Add nodes
    graph.add_node("rag_enrichment", rag_enrichment)
    graph.add_node("code_analyzer", code_analyzer)
    graph.add_node("security_agent", security_agent)
    graph.add_node("fix_generator", fix_generator)
    graph.add_node("explanation_agent", explanation_agent)
    graph.add_node("reviewer", reviewer)

    # Define the edges (linear pipeline)
    if _has_start:
        graph.add_edge(START, "rag_enrichment")
    else:
        graph.set_entry_point("rag_enrichment")

    graph.add_edge("rag_enrichment", "code_analyzer")
    graph.add_edge("code_analyzer", "security_agent")
    graph.add_edge("security_agent", "fix_generator")
    graph.add_edge("fix_generator", "explanation_agent")
    graph.add_edge("explanation_agent", "reviewer")
    graph.add_edge("reviewer", END)

    # Compile
    compiled = graph.compile()
    logger.info("Security review graph compiled successfully")

    return compiled


# Module-level compiled graph (singleton)
_compiled_graph = None


def get_review_graph():
    """Returns the compiled review graph (cached singleton)."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_review_graph()
    return _compiled_graph


def run_review(diffs: List[Dict]) -> List[Dict]:
    """
    Convenience function to run the full security review pipeline.

    Args:
        diffs: List of file diffs, each with 'filename', 'patch', 'status', 'language'

    Returns:
        List of VulnerabilityFinding dictionaries
    """
    graph = get_review_graph()

    logger.info(f"Starting security review for {len(diffs)} files")
    result = graph.invoke({"code_diffs": diffs})

    final_review = result.get("final_review", [])
    logger.info(f"Security review complete: {len(final_review)} vulnerabilities found")

    return final_review
