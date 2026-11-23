"""Minimal, dependency-free client for the Anthropic Messages API."""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Protocol

DEFAULT_MODEL = "claude-sonnet-5-5"   # patches: the strongest per dollar
TRIAGE_MODEL = "claude-haiku-5-5"     # explanations and verdicts: 20x cheaper

# USD per million tokens (input, output), from Anthropic's pricing page (November 2026).
# Haiku 5.5 costs more above 100,000 prompt tokens. Unknown models are priced high on purpose.
PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
}
LONG_PROMPT = {"claude-haiku-5-5": (100_000, (0.50, 2.50))}
UNKNOWN_PRICE = (10.00, 50.00)
DEFAULT_BUDGET = 0.25                 # USD per run unless AEGIS_AI_BUDGET says otherwise
API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


class AIError(RuntimeError):
    pass


class BudgetExceeded(AIError):
    pass


def price(model: str, input_tokens: int, output_tokens: int) -> float:
    rate_in, rate_out = PRICES.get(model, UNKNOWN_PRICE)
    limit, long_rates = LONG_PROMPT.get(model, (None, None))
    if limit and input_tokens > limit:
        rate_in, rate_out = long_rates
    return (input_tokens * rate_in + output_tokens * rate_out) / 1_000_000


class Spending:
    """Money guard shared by every client of one run, plus a ledger on disk across runs.

    Before each request the worst case (whole prompt + max_tokens of output) must fit in what is
    left; after it, the real cost from the API's usage block is recorded.
    """

    def __init__(self, budget: float | None = None, total_cap: float | None = None, ledger: str | None = None):
        env_budget = os.environ.get("AEGIS_AI_BUDGET")
        env_cap = os.environ.get("AEGIS_AI_TOTAL_BUDGET")
        self.budget = budget if budget is not None else float(env_budget) if env_budget else DEFAULT_BUDGET
        self.total_cap = total_cap if total_cap is not None else float(env_cap) if env_cap else None
        self.ledger = ledger or os.environ.get("AEGIS_AI_LEDGER") or os.path.join(
            os.path.expanduser("~"), ".aegis", "ai-spend.json")
        self.spent = 0.0
        self.calls = 0
        self.tokens = [0, 0]

    def total(self) -> float:
        try:
            with open(self.ledger, encoding="utf-8") as fh:
                return float(json.load(fh).get("total_usd", 0.0))
        except (OSError, ValueError):
            return 0.0

    def check(self, model: str, prompt_chars: int, max_tokens: int) -> None:
        worst = price(model, prompt_chars // 3 + 50, max_tokens)  # ~3 chars per token for code
        if self.spent + worst > self.budget:
            raise BudgetExceeded(f"AI budget for this run reached (${self.spent:.3f} of ${self.budget:.2f}); "
                                 "raise it with AEGIS_AI_BUDGET or --ai-budget")
        if self.total_cap is not None and self.total() + worst > self.total_cap:
            raise BudgetExceeded(f"total AI cap reached (${self.total():.2f} of ${self.total_cap:.2f}, "
                                 f"ledger {self.ledger})")

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        cost = price(model, input_tokens, output_tokens)
        self.spent += cost
        self.calls += 1
        self.tokens[0] += input_tokens
        self.tokens[1] += output_tokens
        try:
            os.makedirs(os.path.dirname(self.ledger), exist_ok=True)
            total = self.total() + cost
            tmp = self.ledger + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"total_usd": round(total, 6), "updated": time.strftime("%Y-%m-%d %H:%M:%S")}, fh)
            os.replace(tmp, self.ledger)
        except OSError:
            pass
        return cost

    def summary(self) -> str:
        line = (f"Claude: {self.calls} request(s), {self.tokens[0]:,} in / {self.tokens[1]:,} out tokens, "
                f"≈${self.spent:.3f} (budget ${self.budget:.2f}")
        if self.total_cap is not None:
            line += f"; all runs ${self.total():.2f} of ${self.total_cap:.2f}"
        return line + ")"


class LLM(Protocol):
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str: ...


class ClaudeClient:
    """Talks to Claude. The key is read from ANTHROPIC_API_KEY and never logged."""

    def __init__(self, api_key: str | None = None, model: str | None = None,
                 timeout: float = 120.0, max_retries: int = 4, base_url: str | None = None,
                 spending: Spending | None = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or os.environ.get("AEGIS_MODEL", DEFAULT_MODEL)
        self.spending = spending or Spending()
        self.timeout = timeout
        self.max_retries = max_retries
        self.url = base_url or os.environ.get("AEGIS_API_URL", API_URL)
        self.usage = {"input_tokens": 0, "output_tokens": 0, "requests": 0}

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def cheaper(self) -> "ClaudeClient":
        """Same key and the same budget, the low-cost model (for triage and explanations)."""
        return ClaudeClient(self.api_key, os.environ.get("AEGIS_TRIAGE_MODEL", TRIAGE_MODEL), self.timeout,
                            self.max_retries, self.url, self.spending)

    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        if not self.available:
            raise AIError("ANTHROPIC_API_KEY is not set")
        self.spending.check(self.model, len(system) + len(prompt), max_tokens)
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
                self.spending.record(self.model, usage.get("input_tokens", 0) + usage.get("cache_read_input_tokens", 0)
                                     + usage.get("cache_creation_input_tokens", 0), usage.get("output_tokens", 0))
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
