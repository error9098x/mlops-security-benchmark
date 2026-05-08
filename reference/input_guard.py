"""
Reference InputGuardrail.

Demonstrates the input-side LLM control from the benchmark checklist:
  - regex-based prompt-injection blocklist
  - structural validation against a Pydantic schema
  - audit log for every decision

Drop in your own Pydantic schema and adjust the patterns for your domain.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Type, Union

from pydantic import BaseModel, ValidationError

# 18-pattern blocklist covering the most common prompt-injection attempts.
# Each entry is (pattern_id, regex). Pattern IDs are written to the audit log
# so you can see *which* check fired without storing the raw payload.
INJECTION_PATTERNS = [
    ("ignore_previous", r"ignore (all|any|previous|prior) (instructions|prompts|rules)"),
    ("disregard_system", r"disregard (the )?(system|above|previous)"),
    ("role_play", r"pretend (you are|to be)|act as|role[- ]?play|you are now"),
    ("print_instructions", r"print (your|the) (instructions|system prompt|prompt|rules)"),
    ("reveal_system", r"reveal (the )?(system|hidden|secret) (prompt|message|instructions|id|token)"),
    ("delimiter_escape", r"(^|\s)(#{3,}|`{3,}|---END---|<\|.*?\|>|<end_of_turn>)"),
    ("jailbreak_keyword", r"developer mode|jailbreak|\bDAN\b|sudo mode"),
    ("output_initial", r"output (your|the) initial (message|prompt|instructions)"),
    ("summarize_examples", r"summarize your (training|few-shot|in-?context) examples"),
    ("repeat_above", r"repeat (everything|all|the text) (above|before this line)"),
    ("context_dump", r"(print|dump|show) (the )?(contents of (your )?context|context window)"),
    ("ask_internal_id", r"(what is|tell me) your (internal id|id|token|secret)"),
    ("instruction_extract", r"what instructions were you (given|told|programmed with)"),
    ("then_also_print", r"\b(then|also|additionally)\b[^.]{0,40}\b(print|output|emit|reveal|show|reply)\b"),
    ("embedded_command", r"[;|]\s*(also\s+)?(print|output|reveal|emit|run|exec|eval)\b"),
    ("on_deeper", r"on (deeper|closer) (analysis|inspection|reflection|review)"),
    ("base64_payload", r"(?:[A-Za-z0-9+/]{40,}={0,2})"),
    ("sql_like", r"(union\s+select|or\s+1=1|--\s+|;\s*drop\s+table)"),
]


class GuardResult(BaseModel):
    blocked: bool
    reason: str = ""
    matched_pattern: str = ""


class InputGuardrail:
    """Wraps any LLM/API call with a two-layer input check."""

    def __init__(self, schema: Type[BaseModel], audit_path: Union[str, Path] = "audit_input.jsonl"):
        self.schema = schema
        self.audit_path = Path(audit_path)
        self._compiled = [(pid, re.compile(p, re.IGNORECASE | re.DOTALL)) for pid, p in INJECTION_PATTERNS]

    def _scan_blocklist(self, text: str):
        for pid, rx in self._compiled:
            if rx.search(text):
                return pid
        return None

    def _structural_check(self, payload):
        try:
            self.schema.model_validate(payload)
            return None
        except ValidationError as e:
            return f"schema_violation:{e.errors()[0].get('type', 'unknown')}"

    def _audit(self, record):
        record["ts"] = datetime.now(timezone.utc).isoformat()
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    @staticmethod
    def _payload_to_text(payload):
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            return " ".join(str(v) for v in payload.values())
        return str(payload)

    def check(self, payload) -> GuardResult:
        scan_text = self._payload_to_text(payload)
        matched = self._scan_blocklist(scan_text)
        if matched:
            res = GuardResult(blocked=True, reason=f"matched_blocklist:{matched}", matched_pattern=matched)
            self._audit({"outcome": "blocked", "reason": res.reason})
            return res
        struct_err = self._structural_check(payload)
        if struct_err:
            res = GuardResult(blocked=True, reason=struct_err, matched_pattern=struct_err)
            self._audit({"outcome": "blocked", "reason": res.reason})
            return res
        self._audit({"outcome": "passed"})
        return GuardResult(blocked=False)
