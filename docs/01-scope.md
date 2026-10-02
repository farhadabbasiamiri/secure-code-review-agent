# Week 1 — Project Scope

**Project:** Secure Code Review Agent for Web Apps and JavaScript (Group 9B brief)
**Course:** Applied AI Agents for Cybersecurity Operations, Fall 2026
**Developer:** om

## Problem

Web applications ship client- and server-side vulnerabilities (XSS, injection, insecure
cookies, leaked secrets, vulnerable dependencies) that could be caught at pull-request time.
Static analysers find patterns but produce terse output that developers often ignore;
generic LLM chat is fluent but ungrounded and inconsistent.

## Goal

An AI agent that reviews a small JavaScript/Node file or unified diff, runs real analysis
tools, grounds its explanation in OWASP/CWE guidance, and returns structured findings a
developer can act on.

## Intended user

A developer or reviewer looking at a pull request for a small Node/Express or browser JS
change. Not a pentester, not a SOC analyst.

## MVP inputs

- One `.js` / `.mjs` / `.cjs` file (≤ 200 KB), **or**
- A unified diff (`.diff` / `.patch`) touching JS files, **or**
- A `package.json` (dependency check only)

## MVP outputs

For each finding, a JSON object with:
`finding`, `vuln_class`, `cwe`, `evidence` (file, line, snippet), `severity`, `fix`,
`confidence`, `sources` (retrieved OWASP/CWE ids), `tool` (which tool produced the signal).

## Vulnerability classes in scope

| #   | Class                             | CWE                      | Primary detector                      |
| --- | --------------------------------- | ------------------------ | ------------------------------------- |
| 1   | Cross-site scripting              | CWE-79                   | Semgrep custom rules                  |
| 2   | Injection (SQL, OS command, eval) | CWE-89 / CWE-78 / CWE-95 | Semgrep custom rules                  |
| 3   | Insecure cookie                   | CWE-614 / CWE-1004       | Semgrep custom rules                  |
| 4   | Missing input validation          | CWE-20                   | Semgrep custom rules                  |
| 5   | Hardcoded secret                  | CWE-798                  | Semgrep + regex                       |
| 6   | Vulnerable / outdated dependency  | CWE-1395 / CWE-1104      | OSV query (offline snapshot fallback) |

## Out of scope (MVP)

- Whole-repository scanning, TypeScript type-aware analysis, framework-specific taint tracking
- Running or executing uploaded code
- Auto-applying patches to a repository
- Languages other than JavaScript

## Acceptance criteria (from the SDLC guide, mapped)

- [x] Gradio app accepts a JS file / diff (Week 5)
- [x] Agent uses an LLM and ≥1 working tool (Week 4; provider plumbing tested with faked HTTP,
      a run against a live model is still to be recorded)
- [x] Agent visibly selects and executes tools: trace is logged and shown live in the UI (Week 5)
- [x] Actionable result supported by evidence (Week 4)
- [x] Handles invalid input, timeouts, tool failures (Week 6: demo cases + tests)
- [x] Evaluated with documented test cases (Week 6: held-out set, rubric, demo cases, safety)
- [x] Reproducibly runnable: Python, Docker, Compose; Hugging Face Space instructions (Week 7;
      the public Space itself is not published yet)
- [x] README + architecture diagram (Week 7)
- [ ] Live demonstration and final presentation (early December)
