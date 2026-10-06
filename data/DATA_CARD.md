# Data Card — Toy Vulnerable JavaScript Samples

## Summary
18 small, hand-written JavaScript / Node files, one unified diff, and two `package.json`
manifests, labeled with the vulnerability class and line of each intended issue.
Ground truth lives in [`labels.json`](labels.json).

## Purpose
Evaluate whether the agent detects the six MVP vulnerability classes, how often it raises
false positives on fixed or clean code, and whether its evidence points at the right line.

## Composition
| Split | Files | Notes |
|-------|-------|-------|
| Vulnerable | 9 `.js` + 1 `.diff` + 1 manifest | One or more labeled issues each |
| Fixed counterparts | 7 `.js` + 1 manifest | Same code with the issue remediated — the hardest FP test |
| Clean | 2 `.js` | No security-relevant sinks |

Per-class positives: xss 4, injection 4, insecure_cookie 3, missing_input_validation 1,
hardcoded_secret 4, vulnerable_dependency 4 (packages).

## Labeling rules
- A label marks the **sink line** (where unsafe data is used), except SQL injection where it
  marks the line that builds the query string.
- Diff labels use the line number in the **new** file.
- `acceptable` lists classes that are reasonable extra findings (e.g. "missing input
  validation" on a handler that is also injectable). They count neither as TP nor FP.
- A prediction matches a label if the class matches and the line is within ±2.

## Provenance and safety
- All code is synthetic, written for this project. No real applications, no real secrets.
- Secrets are documented placeholder values (e.g. AWS's published `AKIAIOSFODNN7EXAMPLE`).
- Files are never executed by the agent or the evaluation harness.

## Held-out set (Week 6)
13 inputs in [`heldout/`](heldout/), ground truth in [`heldout_labels.json`](heldout_labels.json).
Written on 30 Oct 2026 **after** the Semgrep rules were frozen, and labelled by what a human
reviewer would report rather than by what the rules are known to catch. It deliberately includes:

- variants of covered patterns (template-literal SQL with `pg`, `insertAdjacentHTML` from
  `postMessage`, `child.exec` with an unusual import name, a cookie missing only `secure`);
- patterns the rules don't cover (`findOneAndUpdate(req.body)`, an npm alias of a vulnerable package);
- false-positive bait (a header-name constant called `TOKEN_HEADER`, a number written to `innerHTML`,
  `RegExp.exec`, escaped output, `execFile` with an argument array);
- a diff whose vulnerable `eval` sits on an unchanged context line (must not be reported).

Per-class positives: xss 2, injection 2, insecure_cookie 3, missing_input_validation 2,
hardcoded_secret 1, vulnerable_dependency 3. Rules must not be tuned against this set; once it has
been used to fix rules, it becomes development data and a new held-out set is needed.

## Demo scenarios
[`demo/`](demo/) holds four unlabelled inputs for the UI and demo cases: a prompt-injection comment,
an insecure `express-session` config, a React component the rules do not cover, and a text file
that must be rejected. Descriptions are in `demo/scenarios.json`.

## Known limitations
- Small and single-author: results show the pipeline works, not real-world recall.
- Express-heavy; few browser-framework (React/Vue) patterns.
- Missing-input-validation is under-represented (1 development, 2 held-out positives) and
  inherently fuzzy.
