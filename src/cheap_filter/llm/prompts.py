"""Prompt templates for vulnerability verification."""

from __future__ import annotations

from ..filters.base import SuspiciousRegion, VulnClass

SYSTEM_PROMPT = """\
You are an expert C++ security auditor specializing in memory safety vulnerabilities.
You will be shown a code snippet that has been flagged by a static analysis tool.
Your job is to determine whether the flagged region contains a **real, exploitable vulnerability**.

For each analysis, respond in this exact JSON structure:
{
  "verdict": "confirmed" | "false_positive" | "uncertain",
  "vuln_class": "<class>",
  "severity": "critical" | "high" | "medium" | "low" | "none",
  "explanation": "<concise explanation, ≤3 sentences>",
  "exploit_sketch": "<brief description of how this could be exploited, or null if not exploitable>",
  "line_of_interest": <line number most relevant to the bug, or null>
}

Be strict: only mark "confirmed" if you can trace a concrete code path to the vulnerability.
Do not hallucinate. If context is insufficient, use "uncertain".\
"""

VULN_GUIDANCE: dict[VulnClass, str] = {
    VulnClass.USE_AFTER_FREE: (
        "Focus on: object lifetime, raw pointer ownership, references into containers that "
        "may be invalidated, JS engine value types (JSValue, Value) and GC interaction."
    ),
    VulnClass.BUFFER_OVERFLOW: (
        "Focus on: array bounds, pointer arithmetic, length calculations, off-by-one errors, "
        "and unchecked user-controlled sizes."
    ),
    VulnClass.INTEGER_OVERFLOW: (
        "Focus on: signed/unsigned mismatch in size calculations, multiplication before bounds check, "
        "truncation from wider to narrower integer types."
    ),
    VulnClass.DOUBLE_FREE: (
        "Focus on: multiple owners of the same heap allocation, error-path cleanup, "
        "and exception safety of destructors."
    ),
    VulnClass.NULL_DEREF: (
        "Focus on: unchecked return values of allocation functions, optional/nullable pointer "
        "dereferences without guards."
    ),
    VulnClass.TYPE_CONFUSION: (
        "Focus on: downcasts without type checks, tagged unions with missing tag validation, "
        "JIT-compiled code that assumes a fixed type layout."
    ),
    VulnClass.MEMORY_LEAK: (
        "Focus on: early returns before free(), exception paths that skip cleanup, "
        "and cycle ownership through raw pointers."
    ),
    VulnClass.UNINITIALIZED: (
        "Focus on: stack variables read on error paths before assignment, "
        "conditionally-initialized fields, and partial struct initialization."
    ),
}


def build_prompt(region: SuspiciousRegion, code_snippet: str) -> str:
    guidance = VULN_GUIDANCE.get(region.vuln_class, "")
    return (
        f"## Static Analysis Report\n"
        f"- **File**: `{region.file.name}`\n"
        f"- **Lines**: {region.line_start}–{region.line_end}\n"
        f"- **Checker**: `{region.checker}`\n"
        f"- **Flagged issue**: {region.message}\n"
        f"- **Vulnerability class**: {region.vuln_class.value}\n"
        f"\n{guidance}\n\n"
        f"## Code Snippet (lines {region.line_start - 20}+)\n"
        f"```cpp\n{code_snippet}\n```\n\n"
        "Analyze and respond with the JSON verdict."
    )
