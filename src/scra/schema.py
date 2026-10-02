"""Output contract for the review agent.

Every finding shown to a user must validate against these models. The LLM's raw output is
parsed into them; anything that does not validate is dropped and logged, never displayed.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class VulnClass(str, Enum):
    XSS = "xss"
    INJECTION = "injection"
    INSECURE_COOKIE = "insecure_cookie"
    MISSING_INPUT_VALIDATION = "missing_input_validation"
    HARDCODED_SECRET = "hardcoded_secret"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Evidence(BaseModel):
    file: str
    line: Optional[int] = Field(default=None, ge=1, description="1-based line; None for dependency findings")
    snippet: str = Field(max_length=500)
    package: Optional[str] = None
    version: Optional[str] = None
    fixed_version: Optional[str] = Field(default=None, description="Lowest patched version, from the advisory")


class Finding(BaseModel):
    finding: str = Field(min_length=5, max_length=200, description="One-line title")
    vuln_class: VulnClass
    cwe: str = Field(pattern=r"^CWE-\d+$")
    evidence: Evidence
    severity: Severity
    explanation: str = Field(max_length=1500)
    fix: str = Field(min_length=5, max_length=2000)
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list, description="Knowledge-base entry ids used")
    tool: str = Field(description="Tool that produced the underlying signal")
    explained_by: str = Field(default="", description="Who wrote the text: the LLM provider name, or 'template'")

    @field_validator("sources")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


class ToolCall(BaseModel):
    tool: str
    arguments: dict
    ok: bool
    duration_ms: int
    summary: str
    error: Optional[str] = None


class ReviewResult(BaseModel):
    review_id: str = Field(default="", description="Random id linking a review to its approval decisions")
    input_name: str
    input_kind: str  # "file" | "diff" | "manifest"
    findings: list[Finding]
    trace: list[ToolCall]
    llm_provider: str
    dropped: int = Field(default=0, description="LLM findings rejected by the validator")
    errors: list[str] = Field(default_factory=list)
    seconds: float = 0.0
