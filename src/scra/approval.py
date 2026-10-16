"""Human approval step (Week 6).

The agent's findings are suggestions. Two actions count as *sensitive* because they leave the
review screen or change code, and both require a human to approve the finding first:

  draft_pr_comments  review comments meant to be posted on a pull request
  draft_patch        a suggested code change (shown as a diff, never applied)

The check is enforced here, not only in the UI: calling either function for a finding that
has not been approved raises ApprovalRequired. Decisions are logged as metadata (class, CWE,
decision) so false-positive feedback can be measured; code and notes are not logged.
"""
from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field

from .agent import _redact_payloads
from .llm import LLMError, MockProvider, Provider
from .logging_utils import log_event
from .schema import Finding, ReviewResult
from .tools import InputError, parse_input
from .tools.retrieve import get_kb
from .tools.semgrep_tool import redact_secrets_in_code

PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"
PATCH_WINDOW = 6  # lines of context either side that an LLM sees when drafting a patch


class ApprovalRequired(PermissionError):
    """Raised when a sensitive action is attempted on a finding nobody approved."""


@dataclass
class ReviewSession:
    """One review plus the reviewer's decisions. Lives in UI session memory only."""

    result: ReviewResult
    raw_text: str
    decisions: dict[int, str] = field(default_factory=dict)

    def decision(self, index: int) -> str:
        return self.decisions.get(index, PENDING)

    def decide(self, index: int, decision: str) -> None:
        if decision not in (PENDING, APPROVED, REJECTED):
            raise ValueError(f"unknown decision {decision!r}")
        if not 0 <= index < len(self.result.findings):
            raise IndexError(f"no finding #{index + 1}")
        if self.decisions.get(index, PENDING) == decision:
            return
        self.decisions[index] = decision
        f = self.result.findings[index]
        log_event("decision", review_id=self.result.review_id, decision=decision, vuln_class=f.vuln_class.value,
                  cwe=f.cwe, tool=f.tool, confidence=f.confidence, provider=self.result.llm_provider)

    def approved(self) -> list[int]:
        return [i for i in range(len(self.result.findings)) if self.decision(i) == APPROVED]

    def require(self, index: int) -> Finding:
        if self.decision(index) != APPROVED:
            raise ApprovalRequired(f"Finding #{index + 1} has not been approved by a reviewer.")
        return self.result.findings[index]


# ------------------------------------------------------------------ PR comments
def _location(f: Finding) -> str:
    return f"{f.evidence.file}:{f.evidence.line}" if f.evidence.line else f.evidence.file


def _sources_md(f: Finding) -> str:
    kb = get_kb().by_id
    links = [f"[{s}]({kb[s]['url']})" if s in kb else s for s in f.sources]
    return ", ".join(links)


def draft_pr_comments(session: ReviewSession) -> tuple[str, list[dict]]:
    """Markdown summary plus GitHub-style review comments ({path, line, body}) for approved findings.

    Nothing is posted anywhere: the reviewer copies or downloads the text.
    """
    approved = session.approved()
    if not approved:
        raise ApprovalRequired("Approve at least one finding before drafting PR comments.")
    comments, blocks = [], []
    for i in approved:
        f = session.result.findings[i]
        body = (f"**[{f.severity.value.upper()}] {f.finding}**\n\n"
                f"{f.cwe} · confidence {f.confidence:.2f} · detected by `{f.tool}`\n\n"
                f"**Why:** {f.explanation}\n\n**Suggested fix:** {f.fix}"
                + (f"\n\n**References:** {_sources_md(f)}" if f.sources else ""))
        comments.append({"path": f.evidence.file, "line": f.evidence.line, "body": body})
        blocks.append(f"#### `{_location(f)}`\n\n```\n{f.evidence.snippet}\n```\n\n{body}")
    skipped = len(session.result.findings) - len(approved)
    header = (f"### Security review: {len(approved)} approved finding(s) in `{session.result.input_name}`\n\n"
              f"_Drafted by the Secure Code Review Agent ({session.result.llm_provider}); every comment below "
              f"was approved by a human reviewer."
              + (f" {skipped} other finding(s) were rejected or left undecided and are not included." if skipped else "")
              + "_\n\n")
    log_event("pr_comments_drafted", review_id=session.result.review_id, count=len(approved))
    return header + "\n\n---\n\n".join(blocks), comments


# ------------------------------------------------------------------ Patches
@dataclass
class PatchDraft:
    diff: str
    method: str  # "rule" | "llm" | "none"
    note: str


def _target_text(session: ReviewSession, f: Finding) -> tuple[str, str]:
    """(path, text) of the file the finding points at. Diffs use their post-change view."""
    try:
        parsed = parse_input(session.result.input_name, session.raw_text)
    except InputError:
        return f.evidence.file, session.raw_text
    for sf in parsed.files:
        if sf.path == f.evidence.file:
            return sf.path, sf.text
    return f.evidence.file, session.raw_text


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


# Expression pieces of a JS string built by concatenation or a template literal.
def _segments(arg: str) -> list[tuple[str, str]] | None:
    """Split `"a " + x + "b"` or `` `a ${x}b` `` into [("lit","a "),("expr","x"),("lit","b")]."""
    arg = arg.strip()
    if arg.startswith("`") and arg.endswith("`"):
        out, body, pos = [], arg[1:-1], 0
        for m in re.finditer(r"\$\{([^}]*)\}", body):
            if m.start() > pos:
                out.append(("lit", body[pos:m.start()]))
            out.append(("expr", m.group(1).strip()))
            pos = m.end()
        if pos < len(body):
            out.append(("lit", body[pos:]))
        return out
    parts = [p.strip() for p in re.split(r"\s\+\s", arg)]
    out = []
    for p in parts:
        m = re.fullmatch(r"([\"'])(.*)\1", p)
        if m:
            out.append(("lit", m.group(2)))
        elif re.fullmatch(r"[\w$.\[\]()'\"]+", p):
            out.append(("expr", p))
        else:
            return None
    return out


def _js_str(s: str) -> str:
    return json.dumps(s)


def _env_name(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).upper()


def _rule_patch(f: Finding, lines: list[str]) -> tuple[list[str], str] | None:
    """Deterministic rewrite for common cases. Returns (new_lines, note) or None."""
    if f.evidence.line is None:
        return _dependency_patch(f, lines)
    i = f.evidence.line - 1
    if not 0 <= i < len(lines):
        return None
    line, new = lines[i], list(lines)
    cls = f.vuln_class.value

    if cls == "xss":
        m = re.match(r"(\s*)([\w$.]+)\.innerHTML\s*\+=\s*\"<(\w+)>\"\s*\+\s*(.+?)\s*\+\s*\"</\3>\";?\s*$", line)
        if m:  # list.innerHTML += "<li>" + x + "</li>"  ->  build the element, set its text
            ind, parent, tag, expr = m.groups()
            el = f"{tag}El"
            new[i:i + 1] = [f'{ind}const {el} = document.createElement("{tag}");',
                            f"{ind}{el}.textContent = {expr};", f"{ind}{parent}.appendChild({el});"]
            return new, "Builds the element and sets its text, so the value is never parsed as HTML."
        if re.search(r"\.(innerHTML|outerHTML)\s*=", line):
            new[i] = re.sub(r"\.(innerHTML|outerHTML)\s*=", ".textContent =", line)
            return new, "Writes the value as text instead of parsing it as HTML."
        if "insertAdjacentHTML(" in line:
            new[i] = line.replace("insertAdjacentHTML(", "insertAdjacentText(")
            return new, "Inserts the value as text instead of HTML."
        m = re.search(r"(\.(?:send|write|end)\()(.*)\)(;?)\s*$", line)
        if m:
            segs = _segments(m.group(2))
            if segs and any(k == "expr" for k, _ in segs):
                if m.group(2).strip().startswith("`"):
                    inner = "".join(v if k == "lit" else "${escapeHtml(" + v + ")}" for k, v in segs)
                    arg = "`" + inner + "`"
                else:
                    arg = " + ".join(_js_str(v) if k == "lit" else f"escapeHtml({v})" for k, v in segs)
                new[i] = line[: m.start(2)] + arg + line[m.end(2):]
                if not any("escape-html" in l for l in lines):
                    new.insert(0, 'const escapeHtml = require("escape-html");')
                return new, "HTML-encodes each dynamic value (npm package escape-html)."
        return None

    if cls == "insecure_cookie":
        if ".cookie(" in line:
            m = re.search(r"(\.cookie\(\s*[^,]+,\s*[^,)]+?)\s*\)", line)
            if m:  # no options object at all
                new[i] = line[: m.end(1)] + ', { httpOnly: true, secure: true, sameSite: "lax" })' + line[m.end():]
                return new, "Adds httpOnly, secure and sameSite to the cookie options."
            m = re.search(r"\{(.*)\}", line)
            if not m:
                return None
            opts = re.sub(r"\b(httpOnly|secure)\s*:\s*false", r"\1: true", m.group(1)).strip().rstrip(",")
            for flag in ("httpOnly", "secure"):
                if flag not in opts:
                    opts += f", {flag}: true"
            if "sameSite" not in opts:
                opts += ', sameSite: "lax"'
            new[i] = line[: m.start(1)] + " " + opts.lstrip(", ") + " " + line[m.end(1):]
            return (new, "Turns on httpOnly and secure and sets sameSite.") if new[i] != line else None
        # session({ cookie: { ... } }) may span several lines: fix flags up to the end of the call.
        for j in range(i, min(i + 12, len(lines))):
            new[j] = re.sub(r"\b(httpOnly|secure)\s*:\s*false", r"\1: true", new[j])
            if "})" in lines[j]:
                break
        return (new, "Turns on httpOnly and secure for the session cookie.") if new != lines else None

    if cls == "hardcoded_secret":
        m = re.match(r"(\s*(?:const|let|var)\s+)(\w+)(\s*=\s*)([\"'`]).*\4(;?)\s*$", line)
        if m:
            new[i] = f"{m.group(1)}{m.group(2)}{m.group(3)}process.env.{_env_name(m.group(2))};"
            return new, f"Reads the value from the {_env_name(m.group(2))} environment variable. Rotate the exposed value."
        m = re.match(r"(\s*)([\w\"']+)(\s*:\s*)([\"'`]).*\4(,?)\s*$", line)
        if m:
            key = m.group(2).strip("\"'")
            new[i] = f"{m.group(1)}{m.group(2)}{m.group(3)}process.env.{_env_name(key)}{m.group(5)}"
            return new, f"Reads the value from the {_env_name(key)} environment variable. Rotate the exposed value."
        return None

    if cls == "injection":
        if f.cwe == "CWE-95":
            m = re.search(r"\beval\((.*)\)", line)
            if m:
                new[i] = line[: m.start()] + f"JSON.parse({m.group(1)})" + line[m.end():]
                new.insert(i, _indent(line) + "// If this must evaluate arithmetic, use a real expression parser instead.")
                return new, "Parses the input as data. Code evaluation is removed."
            return None
        if f.cwe == "CWE-89":
            return _sql_patch(lines, i)
        if f.cwe == "CWE-78":
            return _cmd_patch(lines, i)
        return None

    if cls == "missing_input_validation":
        m = re.search(r"(\w+(?:\.\w+)*)\.(create|insertOne|insertMany)\(\s*(\w+)\.body\s*\)", line)
        if m:
            ind = _indent(line)
            new[i] = line.replace(f"{m.group(3)}.body", "parsed.data")
            new[i:i] = [f"{ind}// Input: a zod schema that lists the allowed fields, e.g. z.object({{ name: z.string() }})",
                        f"{ind}const parsed = Input.safeParse({m.group(3)}.body);",
                        f'{ind}if (!parsed.success) return res.status(400).json({{ error: "invalid input" }});']
            return new, "Validates the body against a schema and passes only the parsed fields on. Define `Input` with zod."
        return None
    return None


def _sql_patch(lines: list[str], i: int) -> tuple[list[str], str] | None:
    line, new = lines[i], list(lines)
    m = re.match(r"(\s*(?:const|let|var)\s+)(\w+)(\s*=\s*)(.*?);?\s*$", line)
    if not m:
        return None
    segs = _segments(m.group(4))
    if not segs:
        return None
    sql, params = "", []
    for k, v in segs:
        if k == "lit":
            sql += v
        else:
            sql = re.sub(r"(['\"])$", "", sql) + "?"
            params.append(v)
    sql = re.sub(r"\?(['\"])", "?", sql)
    if not params:
        return None
    var = m.group(2)
    new[i] = f"{m.group(1)}{var}{m.group(3)}{_js_str(sql)};"
    for j in range(i + 1, min(i + 10, len(lines))):
        c = re.search(rf"\.(query|execute)\(\s*{var}\s*([,)])", new[j])
        if c:
            insert = f", [{', '.join(params)}]" + ("," if c.group(2) == "," else ")")
            new[j] = new[j][: c.start(2)] + insert + new[j][c.end(2):]
            return new, "Keeps the SQL text constant and passes values as parameters."
    return None


def _cmd_patch(lines: list[str], i: int) -> tuple[list[str], str] | None:
    line, new = lines[i], list(lines)
    m = re.search(r"\b(?:\w+\.)?(exec|execSync)\((`[^`]*`|[^,)]*(?:\s\+\s[^,)]*)*)(\s*[,)])", line)
    if not m:
        return None
    segs = _segments(m.group(2))
    if not segs:
        return None
    tokens: list[list[tuple[str, str]]] = [[]]
    for k, v in segs:
        if k == "expr":
            tokens[-1].append((k, v))
            continue
        for piece in re.split(r"(\s+)", v):
            if piece.isspace():
                if tokens[-1]:
                    tokens.append([])
            elif piece:
                tokens[-1].append(("lit", piece))
    tokens = [t for t in tokens if t]
    if len(tokens) < 1 or tokens[0][0][0] != "lit" or len(tokens[0]) != 1:
        return None

    def render(tok):
        if len(tok) == 1:
            return _js_str(tok[0][1]) if tok[0][0] == "lit" else tok[0][1]
        return " + ".join(_js_str(v) if k == "lit" else v for k, v in tok)

    fn = "execFileSync" if m.group(1) == "execSync" else "execFile"
    call = f'{fn}({_js_str(tokens[0][0][1])}, [{", ".join(render(t) for t in tokens[1:])}]'
    new[i] = line[: m.start()] + call + line[m.end(2):]
    for j, l in enumerate(new):
        r = re.search(r"\{\s*([\w\s,]*)\}\s*=\s*require\([\"']child_process[\"']\)", l)
        if r:
            names = [n.strip() for n in r.group(1).split(",") if n.strip()]
            still_used = any(re.search(rf"\b{m.group(1)}\(", x) for k, x in enumerate(new) if k != j)
            names = [n for n in names if n != m.group(1) or still_used]
            if fn not in names:
                names.append(fn)
            new[j] = l[: r.start(1)].rstrip() + " " + ", ".join(names) + " " + l[r.end(1):].lstrip()
            break
    return new, ("Runs the program directly with an argument array, so the input can't add shell commands. "
                 "Still validate it (for a host: net.isIP or an allow-list).")


def _dependency_patch(f: Finding, lines: list[str]) -> tuple[list[str], str] | None:
    pkg, fixed = f.evidence.package, f.evidence.fixed_version
    if not pkg or not fixed:
        return None
    new = list(lines)
    for i, l in enumerate(lines):
        m = re.match(rf'(\s*"{re.escape(pkg)}"\s*:\s*")([^"]+)(".*)$', l)
        if m:
            new[i] = f"{m.group(1)}^{fixed}{m.group(3)}"
            return new, f"Upgrades {pkg} to {fixed}, the lowest patched release. Regenerate the lockfile and re-run tests."
    return None


PATCH_PROMPT = """You fix one security issue in a JavaScript file. You receive numbered lines
(secrets are masked) and the issue. Reply with ONLY JSON: {"replacement": "<the corrected
lines, covering exactly lines START to END>"}. Change as little as possible. Do not add
exploit examples. Keep masked values masked; prefer process.env for secrets."""


def _llm_patch(provider: Provider, f: Finding, lines: list[str]) -> tuple[list[str], str] | None:
    if f.evidence.line is None:
        return None
    lo, hi = max(0, f.evidence.line - 1 - PATCH_WINDOW), min(len(lines), f.evidence.line + PATCH_WINDOW)
    masked = redact_secrets_in_code("\n".join(lines)).split("\n")
    window = "\n".join(f"{n + 1:>4} {masked[n]}" for n in range(lo, hi))
    user = (f"Issue: {f.finding} ({f.cwe}) at line {f.evidence.line}.\nGuidance: {f.fix}\n"
            f"START={lo + 1} END={hi}\n\n{window}")
    try:
        reply = provider.chat([{"role": "system", "content": PATCH_PROMPT}, {"role": "user", "content": user}], [])
        text = reply.content.strip()
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
        data = json.loads(text[text.find("{"): text.rfind("}") + 1])
        replacement = str(data["replacement"])
    except (LLMError, ValueError, KeyError, TypeError):
        return None
    rep_lines = _redact_payloads(replacement).split("\n")
    if len(rep_lines) > 3 * (hi - lo) + 10:
        return None
    return lines[:lo] + rep_lines + lines[hi:], "Drafted by the LLM from the finding and fix guidance. Review it carefully."


def draft_patch(session: ReviewSession, index: int, provider: Provider | None = None) -> PatchDraft:
    """Suggested change for one approved finding, as a unified diff. Never applied to anything."""
    f = session.require(index)
    path, text = _target_text(session, f)
    lines = text.split("\n")
    result, method = None, "none"
    if provider is not None and not isinstance(provider, MockProvider):
        result = _llm_patch(provider, f, lines)
        method = "llm" if result else "none"
    if result is None:
        result = _rule_patch(f, lines)
        method = "rule" if result else "none"
    log_event("patch_drafted", review_id=session.result.review_id, vuln_class=f.vuln_class.value,
              cwe=f.cwe, method=method)
    if result is None:
        return PatchDraft("", "none", "No automatic patch for this pattern. Follow the fix guidance: " + f.fix)
    new_lines, note = result
    # Mask secrets on both sides so the diff never shows the original value.
    before = redact_secrets_in_code("\n".join(lines)).split("\n")
    after = redact_secrets_in_code("\n".join(new_lines)).split("\n")
    diff = "\n".join(difflib.unified_diff(before, after, f"a/{path}", f"b/{path}", n=2, lineterm=""))
    if not diff:
        return PatchDraft("", "none", "The draft did not change anything. Follow the fix guidance: " + f.fix)
    return PatchDraft(diff, method, note)
