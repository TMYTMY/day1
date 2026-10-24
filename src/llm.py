"""OpenRouter-compatible chat client. The API key stays in the Authorization header."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import requests

from src.config import redact

PostFunc = Callable[..., requests.Response]


class LlmError(Exception):
    """The language model request failed. The message is already redacted."""


class LlmClient:
    def __init__(
        self,
        api_key: str | None,
        base_url: str,
        model: str,
        *,
        timeout: float = 45,
        post: PostFunc | None = None,
    ):
        self.api_key = (api_key or "").strip()
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._post = post or requests.post

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def complete(self, messages: list[dict[str, str]]) -> str:
        if not self.configured:
            raise LlmError("OpenRouter API key is not configured.")
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Title": "Day 1",
        }
        payload = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 800,
            "messages": messages,
        }
        try:
            response = self._post(url, headers=headers, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            raise LlmError(self._redact(f"Language model request failed: {exc}")) from None
        if response.status_code != 200:
            body = (response.text or "")[:400]
            raise LlmError(self._redact(f"Language model returned HTTP {response.status_code}: {body}"))
        try:
            data = response.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise LlmError("Language model returned an unexpected response.") from None
        if not isinstance(content, str):
            raise LlmError("Language model returned an unexpected response.")
        return content

    def _redact(self, text: str) -> str:
        return redact(text, self.api_key)


def parse_model_output(text: str) -> tuple[str, str]:
    """Pull SQL and a short assumption string out of a model response."""
    raw = (text or "").strip()
    if not raw:
        return "", ""
    for candidate in _json_candidates(raw):
        parsed = _json_object(candidate)
        if parsed is not None and "sql" in parsed:
            sql = str(parsed.get("sql") or "").strip()
            assumptions = str(parsed.get("assumptions") or "").strip()[:500]
            return sql, assumptions
    fenced = re.search(r"```sql\s*([\s\S]*?)```", raw, flags=re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip(), ""
    naked = re.search(r"(?is)\b(?:with|select)\b[\s\S]*", raw)
    if naked:
        return naked.group(0).strip().strip("`"), ""
    return "", raw[:500]


def _json_candidates(text: str) -> list[str]:
    candidates = [text]
    for match in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE):
        candidates.append(match.group(1).strip())
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])
    return candidates


def _json_object(text: str) -> dict | None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(value, dict):
        return value
    return None
