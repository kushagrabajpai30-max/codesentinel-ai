"""
Pydantic schemas for the FastAPI request/response layer.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class FileDiffSchema(BaseModel):
    """A single file diff from a pull request."""
    filename: str
    patch: str
    status: str = "modified"
    language: str = "unknown"


class AnalysisRequest(BaseModel):
    """Request body from Spring Boot backend."""
    pr_event_id: int = Field(alias="prEventId")
    repo_full_name: str = Field(alias="repoFullName")
    pr_number: int = Field(alias="prNumber")
    diffs: List[FileDiffSchema]

    model_config = {"populate_by_name": True}


class VulnerabilityFindingSchema(BaseModel):
    """A single vulnerability finding in the response."""
    file: str
    line_number: Optional[int] = Field(default=None, alias="lineNumber")
    vulnerability: str
    severity: str
    issue: str
    fix: str
    explanation: str
    owasp: str

    model_config = {"populate_by_name": True}


class AnalysisResponse(BaseModel):
    """Response body sent back to Spring Boot backend."""
    success: bool
    message: str
    findings: List[VulnerabilityFindingSchema] = []
