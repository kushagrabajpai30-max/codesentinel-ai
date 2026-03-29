"""
OWASP Top 10 document loader — loads and chunks markdown guidelines for RAG.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def load_owasp_documents(data_dir: str | None = None) -> list[dict]:
    """
    Load OWASP Top 10 markdown files and split them into semantic chunks.

    Returns a list of dicts with 'content' and 'metadata' keys.
    """
    if data_dir is None:
        data_dir = os.getenv("OWASP_DATA_DIR", "data/owasp")

    data_path = Path(data_dir)

    if not data_path.exists():
        logger.warning(f"OWASP data directory not found: {data_path}")
        return []

    documents = []
    for md_file in sorted(data_path.glob("*.md")):
        logger.info(f"Loading OWASP document: {md_file.name}")

        content = md_file.read_text(encoding="utf-8")
        chunks = _chunk_document(content, md_file.name)

        for i, chunk in enumerate(chunks):
            documents.append({
                "content": chunk,
                "metadata": {
                    "source": md_file.name,
                    "chunk_index": i,
                    "category": _extract_category(md_file.name),
                },
            })

    logger.info(f"Loaded {len(documents)} chunks from {len(list(data_path.glob('*.md')))} OWASP files")
    return documents


def _chunk_document(content: str, filename: str, chunk_size: int = 800, overlap: int = 100) -> list[str]:
    """Split a document into overlapping chunks by sections or fixed size."""
    # First try section-based splitting (by ## headers)
    sections = []
    current_section = []
    current_title = filename

    for line in content.split("\n"):
        if line.startswith("## ") and current_section:
            sections.append("\n".join(current_section))
            current_section = [line]
            current_title = line
        else:
            current_section.append(line)

    if current_section:
        sections.append("\n".join(current_section))

    # If sections are too large, further chunk them
    chunks = []
    for section in sections:
        if len(section) <= chunk_size:
            if section.strip():
                chunks.append(section.strip())
        else:
            # Fixed-size chunking with overlap
            words = section.split()
            for i in range(0, len(words), chunk_size // 5):
                chunk = " ".join(words[i : i + chunk_size // 5 + overlap // 5])
                if chunk.strip():
                    chunks.append(chunk.strip())

    return chunks if chunks else [content.strip()] if content.strip() else []


def _extract_category(filename: str) -> str:
    """Extract the OWASP category from the filename."""
    # e.g., "A03_injection.md" -> "A03 - Injection"
    name = filename.replace(".md", "").replace("_", " ")
    parts = name.split(" ", 1)
    if len(parts) == 2 and parts[0].startswith("A"):
        return f"{parts[0]} - {parts[1].title()}"
    return name
