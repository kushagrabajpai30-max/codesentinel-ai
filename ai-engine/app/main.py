"""
CodeSentinel AI Engine — FastAPI Application.

Provides the REST API gateway for the LangGraph security review pipeline.
"""

from __future__ import annotations

import logging
import os
import time

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models.schemas import AnalysisRequest, AnalysisResponse, VulnerabilityFindingSchema
from app.workflows.security_review import run_review

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── FastAPI Application ────────────────────────────────────────
app = FastAPI(
    title="CodeSentinel AI Engine",
    description="AI-powered secure code review engine using LangGraph multi-agent workflow",
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "UP",
        "service": "CodeSentinel AI Engine",
        "version": "1.0.0",
    }


@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_code(request: AnalysisRequest):
    """
    Analyze code diffs for security vulnerabilities using the LangGraph multi-agent pipeline.

    Accepts file diffs from the Spring Boot backend and runs:
    START → RAG Enrichment → Code Analyzer → Security Agent → Fix Generator →
    Explanation Agent → Reviewer → END
    """
    logger.info(
        f"Received analysis request: repo={request.repo_full_name}, "
        f"PR #{request.pr_number}, {len(request.diffs)} files"
    )

    start_time = time.time()

    try:
        # Convert Pydantic models to dicts for the workflow
        diffs = [
            {
                "filename": d.filename,
                "patch": d.patch,
                "status": d.status,
                "language": d.language,
            }
            for d in request.diffs
        ]

        # Run the LangGraph security review pipeline
        findings = run_review(diffs)

        # Convert to response schema
        response_findings = []
        for f in findings:
            response_findings.append(
                VulnerabilityFindingSchema(
                    file=f.get("file", "unknown"),
                    lineNumber=f.get("line_number"),
                    vulnerability=f.get("vulnerability", "Unknown"),
                    severity=f.get("severity", "MEDIUM"),
                    issue=f.get("issue", "Security issue detected"),
                    fix=f.get("fix", "Review and apply secure coding practices"),
                    explanation=f.get("explanation", "Manual review recommended"),
                    owasp=f.get("owasp", "A04:2021 Insecure Design"),
                )
            )

        elapsed = time.time() - start_time
        logger.info(
            f"Analysis complete: {len(response_findings)} findings in {elapsed:.2f}s"
        )

        return AnalysisResponse(
            success=True,
            message=f"Analysis complete. Found {len(response_findings)} vulnerabilities.",
            findings=response_findings,
        )

    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Analysis failed after {elapsed:.2f}s: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}",
        )


# ── Entry Point ────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
