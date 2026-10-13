"""Embeddings for the knowledge base.

The default embedder is a local hashed-token vector. It needs no API key and
keeps the index on disk. OpenRouter embeddings are used only when
EMBEDDING_PROVIDER=openrouter and a key is present. The key stays in the
Authorization header.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

import numpy as np
import requests

from src.config import Settings, redact

LOCAL_EMBEDDING_ID = "local-hash-v1"
LOCAL_DIM = 256

_STOP = {
    "the",
    "and",
    "for",
    "with",
    "that",
    "this",
    "from",
    "are",
    "was",
    "were",
    "have",
    "has",
    "into",
    "over",
    "what",
    "show",
    "your",
    "about",
}

PostFunc = Callable[..., requests.Response]


def _tokens(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9_]+", text.lower())
    tokens: list[str] = []
    for word in words:
        if word in _STOP or len(word) < 2:
            continue
        tokens.append(word)
        if len(word) >= 6:
            tokens.append(word[:5])
    characters = re.findall(r"[\u4e00-\u9fff]", text)
    tokens.extend(left + right for left, right in zip(characters, characters[1:]))
    if len(characters) == 1:
        tokens.append(characters[0])
    return tokens


def embed_local(texts: list[str]) -> np.ndarray:
    matrix = np.zeros((len(texts), LOCAL_DIM), dtype=np.float32)
    for row, text in enumerate(texts):
        for token in _tokens(text):
            digest = hashlib.blake2s(token.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % LOCAL_DIM
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            matrix[row, bucket] += sign
    return _normalize(matrix)


def _normalize(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


class Embedder:
    def __init__(self, settings: Settings, post: PostFunc | None = None):
        self.settings = settings
        self._post = post or requests.post

    @property
    def provider(self) -> str:
        if self.settings.embedding_provider == "openrouter" and self.settings.embedding_api_key:
            return "openrouter"
        return "local"

    @property
    def embedding_id(self) -> str:
        if self.provider == "openrouter":
            return f"openrouter:{self.settings.embedding_model}"
        return LOCAL_EMBEDDING_ID

    def label(self) -> str:
        if self.provider == "openrouter":
            return self.settings.embedding_model
        return "Local hash"

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            width = LOCAL_DIM if self.provider == "local" else 0
            return np.zeros((0, width), dtype=np.float32)
        if self.provider == "local":
            return embed_local(texts)
        return self._embed_openrouter(texts)

    def _embed_openrouter(self, texts: list[str]) -> np.ndarray:
        key = self.settings.embedding_api_key or ""
        url = self.settings.openrouter_base_url.rstrip("/") + "/embeddings"
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "X-Title": "Fieldnote",
        }
        vectors: list[list[float]] = []
        try:
            for start in range(0, len(texts), 32):
                batch = texts[start : start + 32]
                response = self._post(
                    url,
                    headers=headers,
                    json={"model": self.settings.embedding_model, "input": batch},
                    timeout=45,
                )
                if response.status_code != 200:
                    body = (response.text or "")[:300]
                    raise KnowledgeEmbedError(
                        redact(
                            f"Embedding request returned HTTP {response.status_code}: {body}",
                            key,
                        )
                    )
                payload = response.json()
                ordered = sorted(payload["data"], key=lambda item: item.get("index", 0))
                vectors.extend(item["embedding"] for item in ordered)
        except KnowledgeEmbedError:
            raise
        except requests.RequestException as exc:
            raise KnowledgeEmbedError(redact(f"Embedding request failed: {exc}", key)) from None
        except (ValueError, KeyError, TypeError):
            raise KnowledgeEmbedError("Embedding response could not be read.") from None
        matrix = np.asarray(vectors, dtype=np.float32)
        if matrix.ndim != 2 or matrix.shape[0] != len(texts):
            raise KnowledgeEmbedError("Embedding response had an unexpected shape.")
        return _normalize(matrix)


class KnowledgeEmbedError(Exception):
    """The embedding call failed. The message is already redacted."""
