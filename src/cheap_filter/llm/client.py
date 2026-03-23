"""Claude API client for vulnerability verification.

Uses:
- claude-opus-4-6 with adaptive thinking
- Streaming to avoid timeouts on long code
- Prompt caching on the system prompt (shared across all queries)
- Structured output (JSON) for deterministic parsing
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import anthropic

from ..filters.base import SuspiciousRegion, VulnClass
from .prompts import SYSTEM_PROMPT, build_prompt

MODEL = "claude-opus-4-6"


@dataclass
class VulnVerdict:
    region: SuspiciousRegion
    verdict: str          # "confirmed" | "false_positive" | "uncertain"
    vuln_class: str
    severity: str
    explanation: str
    exploit_sketch: str | None
    line_of_interest: int | None
    input_tokens: int
    output_tokens: int
    cached_tokens: int

    @property
    def is_real(self) -> bool:
        return self.verdict == "confirmed"

    @property
    def cost_usd(self) -> float:
        # Opus 4.6: $5/1M input, $25/1M output; cached input is ~$0.50/1M
        input_cost = (self.input_tokens - self.cached_tokens) * 5e-6
        cache_cost = self.cached_tokens * 0.5e-6
        output_cost = self.output_tokens * 25e-6
        return input_cost + cache_cost + output_cost


class LLMClient:
    def __init__(self, api_key: str | None = None) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)

    def verify(self, region: SuspiciousRegion, code_snippet: str) -> VulnVerdict:
        """Send one flagged region to Claude for verification."""
        prompt = build_prompt(region, code_snippet)

        with self._client.messages.stream(
            model=MODEL,
            max_tokens=1024,
            thinking={"type": "adaptive"},
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            final = stream.get_final_message()

        raw = next(
            (b.text for b in final.content if b.type == "text"), "{}"
        )
        # Strip markdown code fences if present
        if raw.strip().startswith("```"):
            raw = "\n".join(
                line for line in raw.splitlines()
                if not line.strip().startswith("```")
            )

        try:
            data = json.loads(raw.strip())
        except json.JSONDecodeError:
            data = {
                "verdict": "uncertain",
                "vuln_class": region.vuln_class.value,
                "severity": "unknown",
                "explanation": raw[:200],
                "exploit_sketch": None,
                "line_of_interest": None,
            }

        usage = final.usage
        cached = getattr(usage, "cache_read_input_tokens", 0) or 0

        return VulnVerdict(
            region=region,
            verdict=data.get("verdict", "uncertain"),
            vuln_class=data.get("vuln_class", region.vuln_class.value),
            severity=data.get("severity", "unknown"),
            explanation=data.get("explanation", ""),
            exploit_sketch=data.get("exploit_sketch"),
            line_of_interest=data.get("line_of_interest"),
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cached_tokens=cached,
        )

    def verify_batch(
        self,
        items: list[tuple[SuspiciousRegion, str]],
        on_result: "Callable[[VulnVerdict], None] | None" = None,
    ) -> list[VulnVerdict]:
        """Verify a list of (region, snippet) pairs sequentially."""
        verdicts: list[VulnVerdict] = []
        for region, snippet in items:
            v = self.verify(region, snippet)
            verdicts.append(v)
            if on_result:
                on_result(v)
        return verdicts
