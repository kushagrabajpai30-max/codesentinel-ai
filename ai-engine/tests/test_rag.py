"""Tests for the RAG pipeline — OWASP loader."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.rag.owasp_loader import load_owasp_documents, _extract_category, _chunk_document


class TestOwaspLoader:
    """Tests for the OWASP document loader."""

    def test_load_documents(self):
        docs = load_owasp_documents()
        assert len(docs) > 0
        assert all("content" in d for d in docs)
        assert all("metadata" in d for d in docs)

    def test_extract_category(self):
        assert _extract_category("A01_broken_access_control.md") == "A01 - Broken Access Control"
        assert _extract_category("A03_injection.md") == "A03 - Injection"

    def test_chunk_document(self):
        content = "# Title\n\n## Section 1\nContent one.\n\n## Section 2\nContent two."
        chunks = _chunk_document(content, "test.md")
        assert len(chunks) >= 2

    def test_empty_directory(self):
        docs = load_owasp_documents("/nonexistent/path")
        assert docs == []
