"""Cost and effectiveness metrics — the core of the comparison with Anthropic's work."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .llm.client import VulnVerdict


@dataclass
class ScanMetrics:
    # Filter stage
    files_scanned: int = 0
    files_flagged_by_filter: int = 0
    regions_flagged: int = 0

    # LLM stage
    regions_sent_to_llm: int = 0
    confirmed: int = 0
    false_positives: int = 0
    uncertain: int = 0

    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cached_tokens: int = 0

    verdicts: list[VulnVerdict] = field(default_factory=list)

    def record(self, v: VulnVerdict) -> None:
        self.regions_sent_to_llm += 1
        self.total_input_tokens += v.input_tokens
        self.total_output_tokens += v.output_tokens
        self.total_cached_tokens += v.cached_tokens
        self.verdicts.append(v)
        if v.verdict == "confirmed":
            self.confirmed += 1
        elif v.verdict == "false_positive":
            self.false_positives += 1
        else:
            self.uncertain += 1

    @property
    def filter_reduction_ratio(self) -> float:
        """Fraction of files dropped by the filter (1 = dropped everything)."""
        if self.files_scanned == 0:
            return 0.0
        return 1.0 - (self.files_flagged_by_filter / self.files_scanned)

    @property
    def llm_precision(self) -> float:
        """Confirmed / total sent to LLM."""
        if self.regions_sent_to_llm == 0:
            return 0.0
        return self.confirmed / self.regions_sent_to_llm

    @property
    def total_cost_usd(self) -> float:
        return sum(v.cost_usd for v in self.verdicts)

    @property
    def cost_per_confirmed_bug(self) -> float:
        if self.confirmed == 0:
            return float("inf")
        return self.total_cost_usd / self.confirmed

    def summary(self) -> str:
        lines = [
            "=== cheap-filter scan summary ===",
            f"Files scanned       : {self.files_scanned}",
            f"Files after filter  : {self.files_flagged_by_filter}  "
            f"({(1-self.filter_reduction_ratio)*100:.1f}% passed filter)",
            f"Regions to LLM      : {self.regions_sent_to_llm}",
            f"Confirmed bugs      : {self.confirmed}",
            f"False positives     : {self.false_positives}",
            f"Uncertain           : {self.uncertain}",
            f"LLM precision       : {self.llm_precision:.1%}",
            f"Total cost          : ${self.total_cost_usd:.4f}",
            f"Cost / confirmed bug: ${self.cost_per_confirmed_bug:.4f}",
            f"Input tokens        : {self.total_input_tokens:,}  "
            f"(cached: {self.total_cached_tokens:,})",
            f"Output tokens       : {self.total_output_tokens:,}",
        ]
        return "\n".join(lines)
