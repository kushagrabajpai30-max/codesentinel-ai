"""
FAISS Vector Store — RAG pipeline for OWASP security knowledge retrieval.

Initializes FAISS vector store with OWASP Top 10 documents embedded using
sentence-transformers (local) or OpenAI embeddings.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from app.rag.owasp_loader import load_owasp_documents

logger = logging.getLogger(__name__)

_retriever = None


def get_retriever():
    """Returns the initialized FAISS retriever (cached singleton)."""
    global _retriever
    if _retriever is None:
        _retriever = _initialize_retriever()
    return _retriever


def _initialize_retriever():
    """Initialize the FAISS vector store and return a retriever."""
    try:
        from langchain_community.vectorstores import FAISS
        from langchain.schema import Document
    except ImportError:
        logger.error("langchain-community not installed. Install with: pip install langchain-community")
        return None

    # Load OWASP documents
    documents = load_owasp_documents()

    if not documents:
        logger.warning("No OWASP documents found, RAG will be unavailable")
        return None

    # Convert to LangChain Document format
    lc_documents = [
        Document(page_content=doc["content"], metadata=doc["metadata"])
        for doc in documents
    ]

    logger.info(f"Creating FAISS index with {len(lc_documents)} document chunks")

    # Get embeddings
    embeddings = _get_embeddings()
    if embeddings is None:
        return None

    # Check for existing index
    index_dir = os.getenv("FAISS_INDEX_DIR", "data/faiss_index")
    index_path = Path(index_dir)

    try:
        if index_path.exists() and (index_path / "index.faiss").exists():
            logger.info(f"Loading existing FAISS index from {index_path}")
            vectorstore = FAISS.load_local(
                str(index_path), embeddings, allow_dangerous_deserialization=True
            )
        else:
            logger.info("Building new FAISS index...")
            vectorstore = FAISS.from_documents(lc_documents, embeddings)

            # Save index for reuse
            index_path.mkdir(parents=True, exist_ok=True)
            vectorstore.save_local(str(index_path))
            logger.info(f"FAISS index saved to {index_path}")

        # Return retriever with k=5 results
        return vectorstore.as_retriever(search_kwargs={"k": 5})

    except Exception as e:
        logger.error(f"Failed to initialize FAISS: {e}")
        return None


def _get_embeddings():
    """Get the configured embeddings model."""
    provider = os.getenv("EMBEDDING_PROVIDER", "local")

    if provider == "openai":
        return _get_openai_embeddings()
    else:
        return _get_local_embeddings()


def _get_openai_embeddings():
    """Initialize OpenAI embeddings."""
    try:
        from langchain_openai import OpenAIEmbeddings

        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key or api_key == "your-openai-api-key-here":
            logger.warning("No OpenAI API key for embeddings, falling back to local")
            return _get_local_embeddings()

        return OpenAIEmbeddings(api_key=api_key)
    except ImportError:
        logger.warning("langchain-openai not installed, falling back to local embeddings")
        return _get_local_embeddings()


def _get_local_embeddings():
    """Initialize local sentence-transformers embeddings."""
    try:
        from langchain_community.embeddings import HuggingFaceEmbeddings

        model_name = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        logger.info(f"Using local embeddings model: {model_name}")

        return HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )
    except ImportError:
        logger.error("sentence-transformers not installed. Install with: pip install sentence-transformers")
        return None
