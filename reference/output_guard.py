"""
Reference OutputGuardrail.

Demonstrates the output-side LLM control from the benchmark checklist:
  - canary-token leakage detection
  - system-prompt shingle leakage detection
  - format validation against a Pydantic schema
  - audit log for every decision

Plant a SECRET_TOKEN somewhere in your system prompt at runtime. If the model
ever echoes that token (or substantive shingles of the system prompt) into its
output, the guard blocks the response and writes the trigger to the audit log.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Type, Union

from pydantic import BaseModel, ValidationError


class GuardResult(BaseModel):
    blocked: bool
    reason: str = ""
    matched_snippet: str = ""
    parsed: dict = {}


def system_shingles(prompt: str, n: int = 40):
    """Extract sentence-prefix shingles from the system prompt for leakage detection."""
    cleaned = re.sub(r"\s+", " ", prompt.strip())
    sentences = re.split(r"(?<=[.!?])\s+", cleaned)
    return [s[:n] for s in sentences if len(s.strip()) >= 20]


class OutputGuardrail:
    """Scans model output for two failure modes: leakage and format violation."""

    def __init__(
        self,
        schema: Type[BaseModel],
        secret_token: str,
        system_prompt: str,
        extra_patterns=None,
        audit_path: Union[str, Path] = "audit_output.jsonl",
    ):
        self.schema = schema
        self.audit_path = Path(audit_path)
        patterns = [re.compile(re.escape(secret_token), re.IGNORECASE)]
        patterns += [re.compile(re.escape(sh), re.IGNORECASE) for sh in system_shingles(system_prompt)]
        for p in extra_patterns or []:
            patterns.append(re.compile(p, re.IGNORECASE | re.DOTALL))
        self._patterns = patterns

    def _detect_leakage(self, text: str):
        for rx in self._patterns:
            m = rx.search(text)
            if m:
                return rx.pattern[:60], m.group(0)[:80]
        return None, None

    def _parse(self, text: str):
        try:
            data = json.loads(text)
        except Exception:
            m = re.search(r"\{.*?\}", text, re.DOTALL)
            if not m:
                return None
            try:
                data = json.loads(m.group(0))
            except Exception:
                return None
        try:
            return self.schema.model_validate(data)
        except ValidationError:
            return None

    def _audit(self, record):
        record["ts"] = datetime.now(timezone.utc).isoformat()
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def check(self, model_text: str) -> GuardResult:
        text = (model_text or "").strip()
        if not text:
            res = GuardResult(blocked=True, reason="empty_response")
            self._audit({"outcome": "blocked", "reason": res.reason})
            return res
        pat, snippet = self._detect_leakage(text)
        if pat:
            res = GuardResult(blocked=True, reason=f"leakage:{pat}", matched_snippet=snippet)
            self._audit({"outcome": "blocked", "reason": res.reason, "snippet": snippet})
            return res
        parsed = self._parse(text)
        if parsed is None:
            res = GuardResult(blocked=True, reason="format_violation")
            self._audit({"outcome": "blocked", "reason": res.reason})
            return res
        self._audit({"outcome": "passed"})
        return GuardResult(blocked=False, parsed=parsed.model_dump())
