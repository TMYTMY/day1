"""Embeddings for the knowledge base.

The default embedder is a local hashed-token vector. It needs no API key and
keeps the index on disk. OpenRouter embeddings are used only when
EMBEDDING_PROVIDER=openrouter and a key is present. The key stays in the
Authorization header.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

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
CacheGet = Callable[[str], np.ndarray | None]
CachePut = Callable[[str, np.ndarray], None]

# One try plus three retries. Sleep 1s, then 2s, then 4s unless Retry-After says otherwise.
_RETRY_BACKOFF_SECONDS = (1, 2, 4)


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


def _retry_delay(response: requests.Response, fallback: float) -> float:
    """Prefer a numeric or HTTP-date Retry-After header over the backoff."""
    headers = getattr(response, "headers", None)
    raw = headers.get("Retry-After") if headers is not None and hasattr(headers, "get") else None
    if raw is None or raw == "":
        return fallback
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        pass
    try:
        when = parsedate_to_datetime(str(raw))
    except (TypeError, ValueError, IndexError, OverflowError):
        return fallback
    if when is None:
        return fallback
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


class Embedder:
    def __init__(self, settings: Settings, post: PostFunc | None = None):
        self.settings = settings
        self._post = post or requests.post
        self._cache_get: CacheGet | None = None
        self._cache_put: CachePut | None = None

    def bind_cache(self, reader: CacheGet, writer: CachePut) -> None:
        self._cache_get = reader
        self._cache_put = writer

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
        resolved: list[np.ndarray | None] = [None] * len(texts)
        missing: list[int] = []
        for index, text in enumerate(texts):
            cached = self._cache_get(text) if self._cache_get is not None else None
            if cached is None:
                missing.append(index)
            else:
                resolved[index] = cached
        if missing:
            fetched = self._fetch_embeddings(url, headers, key, [texts[index] for index in missing])
            for index, vector in zip(missing, fetched):
                resolved[index] = vector
                if self._cache_put is not None:
                    self._cache_put(texts[index], vector)
        return np.vstack(resolved)

    def _fetch_embeddings(
        self,
        url: str,
        headers: dict[str, str],
        key: str,
        texts: list[str],
    ) -> list[np.ndarray]:
        vectors: list[list[float]] = []
        try:
            for start in range(0, len(texts), 32):
                batch = texts[start : start + 32]
                response = self._post_with_retry(url, headers, key, batch)
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
        normalized = _normalize(matrix)
        return [normalized[row].copy() for row in range(normalized.shape[0])]

    def _post_with_retry(
        self,
        url: str,
        headers: dict[str, str],
        key: str,
        batch: list[str],
    ) -> requests.Response:
        attempts = 1 + len(_RETRY_BACKOFF_SECONDS)
        for attempt in range(attempts):
            response = self._post(
                url,
                headers=headers,
                json={"model": self.settings.embedding_model, "input": batch},
                timeout=45,
            )
            if response.status_code == 200:
                return response
            retryable = response.status_code == 429 or 500 <= response.status_code <= 599
            if not retryable or attempt == attempts - 1:
                body = (response.text or "")[:300]
                raise KnowledgeEmbedError(
                    redact(
                        f"Embedding request returned HTTP {response.status_code}: {body}",
                        key,
                    )
                )
            time.sleep(_retry_delay(response, _RETRY_BACKOFF_SECONDS[attempt]))
        raise KnowledgeEmbedError("Embedding request failed.")


class KnowledgeEmbedError(Exception):
    """The embedding call failed. The message is already redacted."""
