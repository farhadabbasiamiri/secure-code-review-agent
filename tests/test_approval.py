import json

import pytest

from scra import logging_utils
from scra.agent import review
from scra.approval import (APPROVED, REJECTED, ApprovalRequired, ReviewSession, draft_patch, draft_pr_comments)
from scra.llm import LLMReply, Provider


def _session(sample, name, file_name=None):
    raw = sample(name).decode()
    return ReviewSession(review(file_name or name, raw), raw)


def test_sensitive_actions_need_approval(sample):
    s = _session(sample, "mixed_vuln.js")
    with pytest.raises(ApprovalRequired):
        draft_patch(s, 0)
    with pytest.raises(ApprovalRequired):
        draft_pr_comments(s)
    s.decide(0, REJECTED)
    with pytest.raises(ApprovalRequired):
        draft_patch(s, 0)


def test_pr_comments_include_only_approved(sample):
    s = _session(sample, "mixed_vuln.js")
    s.decide(1, APPROVED)
    s.decide(2, REJECTED)
    md, comments = draft_pr_comments(s)
    assert len(comments) == 1 and comments[0]["line"] == s.result.findings[1].evidence.line
    assert "approved by a human reviewer" in md
    assert s.result.findings[2].finding not in md
    assert "ghp_1234567890abcdef" not in md  # snippets in comments are the masked ones


@pytest.mark.parametrize("name,expect_add,expect_remove", [
    ("sqli_vuln.js", 'db.query(sql, [req.params.id],', "+ req.params.id"),
    ("cmdi_vuln.js", 'execFile("ping", ["-c", "1", req.query.host]', "exec(`ping"),
    ("xss_dom_vuln.js", "el.textContent =", "el.innerHTML ="),
    ("cookie_vuln.js", 'httpOnly: true, secure: true, sameSite: "lax"', 'res.cookie("session", token);'),
])
def test_rule_patches(sample, name, expect_add, expect_remove):
    s = _session(sample, name)
    s.decide(0, APPROVED)
    p = draft_patch(s, 0)
    added = [l for l in p.diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l for l in p.diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    assert p.method == "rule"
    assert any(expect_add in l for l in added), p.diff
    assert any(expect_remove in l for l in removed), p.diff


def test_secret_patch_never_shows_the_secret(sample):
    s = _session(sample, "secret_vuln.js")
    for i in range(len(s.result.findings)):
        s.decide(i, APPROVED)
        diff = draft_patch(s, i).diff
        assert "process.env." in diff
        for secret in ("super-secret-signing-key-123", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG"):
            assert secret not in diff


def test_dependency_patch_uses_fixed_version(sample):
    s = _session(sample, "package_vuln.json", "package.json")
    i = next(n for n, f in enumerate(s.result.findings) if f.evidence.package == "lodash")
    assert s.result.findings[i].evidence.fixed_version == "4.17.19"
    s.decide(i, APPROVED)
    assert '+    "lodash": "^4.17.19",' in draft_patch(s, i).diff


class PatchingLLM(Provider):
    name = "patcher"

    def __init__(self):
        self.prompts = []

    def chat(self, messages, tools):
        self.prompts.append(messages[1]["content"])
        return LLMReply(content=json.dumps({"replacement": "const API_TOKEN = process.env.API_TOKEN;\n"
                                                           "<script>alert(1)</script>"}))


def test_llm_patch_is_masked_and_redacted(sample):
    s = _session(sample, "mixed_vuln.js")
    i = next(n for n, f in enumerate(s.result.findings) if f.vuln_class.value == "hardcoded_secret")
    s.decide(i, APPROVED)
    llm = PatchingLLM()
    p = draft_patch(s, i, provider=llm)
    assert p.method == "llm"
    assert "ghp_1234567890abcdef" not in llm.prompts[0]  # the model only sees masked code
    assert "<script>alert" not in p.diff


def test_decisions_are_logged_as_metadata(monkeypatch, tmp_path, sample):
    monkeypatch.delenv("SCRA_DISABLE_LOGS")
    monkeypatch.setattr(logging_utils, "LOG_DIR", tmp_path)
    s = _session(sample, "xss_dom_vuln.js")
    s.decide(0, APPROVED)
    s.decide(0, REJECTED)
    events = (tmp_path / "events.jsonl").read_text().splitlines()
    assert [json.loads(e)["decision"] for e in events] == ["approved", "rejected"]
    assert "innerHTML" not in "".join(events)  # no code in the log
    summary = logging_utils.summarize_logs()
    assert summary["runs"] == 1 and summary["decisions"] == {"approved": 1, "rejected": 1}
