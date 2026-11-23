"""Minimal, dependency-free client for the Anthropic Messages API."""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Protocol

DEFAULT_MODEL = "claude-sonnet-5-5"
API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class AIError(RuntimeError):
    pass


class LLM(Protocol):
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str: ...


class ClaudeClient:
    """Talks to Claude. The key is read from ANTHROPIC_API_KEY and never logged."""

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 timeout: float = 120.0, max_retries: int = 4, base_url: str | None = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("AEGIS_MODEL", DEFAULT_MODEL)
        self.timeout = timeout
        self.max_retries = max_retries
        self.url = base_url or os.environ.get("AEGIS_API_URL", API_URL)
        self.usage = {"input_tokens": 0, "output_tokens": 0, "requests": 0}

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        if not self.available:
            raise AIError("ANTHROPIC_API_KEY is not set")
        body = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        last_error = ""
        for attempt in range(self.max_retries + 1):
            request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(raw)
                except ValueError:
                    raise AIError(f"unexpected non-JSON response from the API: {raw[:200]}") from None
                usage = data.get("usage", {})
                self.usage["input_tokens"] += usage.get("input_tokens", 0)
                self.usage["output_tokens"] += usage.get("output_tokens", 0)
                self.usage["requests"] += 1
                return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
                last_error = f"HTTP {exc.code}: {detail}"
                if exc.code not in RETRY_STATUS or attempt == self.max_retries:
                    raise AIError(last_error) from None
                try:
                    wait = float(exc.headers.get("retry-after") or 0)
                except ValueError:  # an HTTP date instead of seconds
                    wait = 0
                wait = wait or (2 ** attempt + random.random())
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_error = f"network error: {exc}"
                if attempt == self.max_retries:
                    raise AIError(last_error) from None
                wait = 2 ** attempt + random.random()
            time.sleep(min(wait, 30))
        raise AIError(last_error or "request failed")


def parse_json_reply(text: str):
    """Extract the first JSON object/array from a model reply (tolerates ``` fences)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    candidates = sorted(
        (pos, opener, closer)
        for opener, closer in (("{", "}"), ("[", "]"))
        if (pos := text.find(opener)) != -1
    )
    for start, opener, closer in candidates:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    raise AIError("model reply did not contain valid JSON")
