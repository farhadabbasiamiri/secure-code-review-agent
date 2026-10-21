# Try every feature

A guided tour of the app, about 20 minutes with the mock provider. Each step says what to do and
what you should see, so you can tell when something is off. Start the app first (see the README):

```powershell
.venv\Scripts\python -m scra.app      # then open http://127.0.0.1:7860
```

## 1. A first review

1. The editor opens with **Sample: mixed_vuln.js**. Select **Review**.
2. The right side shows *Reviewing...*, and **Agent steps** fills in live: read the input, the model
   decides, Semgrep runs (about 5 s on Windows), then four guidance lookups, then the model writes
   the findings.
3. You get **4 issues**: 1 critical, 2 high, 1 medium.

Read the first finding (it opens automatically):

- The coloured left edge and the label give the severity.
- The boxed line is the evidence: the exact line number and code the tool flagged.
- **Why** and **Fix** are the explanation. **Sources** link to the OWASP/CWE entries that were
  retrieved for this issue.
- The grey line at the bottom says where each part came from: which tool detected it, with what
  confidence, and who wrote the text (the mock provider, a real LLM, or a fixed template).

Click the other findings to expand them. Open **Structured output (JSON)** to see the same result as
data, and download it.

## 2. Fix the code and review again

In the editor, change line 9 to `res.send(`<p>Hi ${escapeHtml(req.query.name)}</p>`);`, then give
line 14 options: `res.cookie("last_backup", req.body.name, { httpOnly: true, secure: true });`.
Review again: **2 issues** remain (the command injection and the hardcoded token). This shows the
rules understand sanitizers, not just keywords.

## 3. Different kinds of input

| Pick this sample | What to look for |
|------------------|------------------|
| `xss_added.diff` | Reviewed as a diff. Only the **added** `innerHTML` line is reported; unchanged lines are ignored, as in a pull request. |
| `package_vuln.json` | Dependency check instead of Semgrep: four vulnerable versions with advisory ids. Untick the snapshot box to query the live OSV database instead (needs internet; results can differ as advisories are published). |
| `sqli_fixed.js` (or any `_fixed` file) | *No issues found*, plus a note that a clean result is not proof the code is safe. |
| `Scenario: session_config.js` | An insecure `express-session` cookie configuration. |
| `Scenario: prompt_injection.js` | The file contains a comment telling the AI reviewer to report nothing. The `eval()` is still reported: detection comes from the tool, and the guard restores anything the model leaves out. |
| `Scenario: react_profile.jsx` | **No findings**, which is wrong: `dangerouslySetInnerHTML` is XSS, but the rules don't cover React yet. A known gap, worth showing honestly. |

## 4. Inputs it should refuse

- `Scenario: notes.txt`: *Input rejected: Unsupported input.*
- Clear the editor and review: *Input is empty.*
- Change the file name to `notes.md` with any content: rejected. The file name decides how the
  input is read (`.js`/`.mjs`/`.cjs`/`.jsx`, `.diff`/`.patch`, `package.json`).
- **Upload a file**: pick any `.exe` or image renamed to `.js`. A warning appears and the editor
  is left unchanged. Uploaded content is never run.

## 5. Approve and export (the human approval step)

1. Review `mixed_vuln.js`, then open **Approve and export**.
2. Select **Draft PR comments** before approving anything: it refuses. That's the point: comments
   meant for a pull request, and patch drafts, need a person's approval first. The check is enforced
   in the backend, not just hidden in the UI.
3. Tick findings 1 and 3 under **Approve** and finding 2 under **Reject (false positive)**. Ticking
   a finding in one list removes it from the other. The status line counts your decisions, and the
   Review tab now marks each finding *Approved* or *Rejected*.
4. **Draft PR comments**: a review summary with only the two approved findings, plus downloadable
   `review-comments.md` and `review-comments.json` (GitHub's `{path, line, body}` format). Nothing
   is posted anywhere.
5. Pick an approved finding and select **Draft a patch**: a unified diff of the suggested change.
   Try it on several samples:
   - `cmdi_vuln.js`: `exec(...)` becomes `execFile("ping", ["-c", "1", host])` and the import is updated.
   - `sqli_vuln.js`: the query becomes parameterised.
   - `secret_vuln.js`: literals become `process.env.NAME`. The *removed* lines in the diff show the
     secret masked too.
   - `package_vuln.json`: the version is bumped to the lowest patched release.

   With the mock provider, patches come from built-in rewrite rules. With a real model, the model
   drafts them from masked code. Either way it's a suggestion: nothing is applied.

## 6. LLM settings

1. Choose **Ollama** without having it installed and select **Test connection**: *nothing is
   answering at that address*. Go back to Review and run a review anyway: you still get every finding,
   with a note that the LLM was unavailable and template text in the explanations.
2. Follow [`LLM_SETUP.md`](LLM_SETUP.md) to connect a real model (Groq is quickest, Ollama keeps
   everything local). **Fetch models** lists what the server offers; **Test connection** checks the
   server, the model, and tool calling.
3. Review `mixed_vuln.js` with the real model and compare: the explanations are written by the
   model, but the line numbers, snippets and tool names are identical. The model cannot change the
   evidence.
4. With a slow local model, set **Whole-review time limit** to 30 s and review: the agent stops,
   notes the time limit, and still shows the tool findings.

## 7. Monitoring

Open **Monitoring** after a few reviews: number of reviews, median and 95th-percentile time, failed
tool calls, findings by class, your approve/reject decisions, providers used, and recent runs. It's
built from `logs/runs.jsonl` and `logs/events.jsonl`, which hold timings and counts, never code or keys.

## 8. Held-out samples

The `Held-out:` samples were written after the rules were frozen, to measure honestly. Try
`h_cmd_alias.js` (caught despite the unusual `child` import name),
`h_validation_findoneandupdate.js` (missed: the rule doesn't know
`findOneAndUpdate`), `h_secret_config.js` (one real secret, plus a false positive on a header
name), and `h_clean_dom.js` (a false positive on a number written to `innerHTML`). Reject the false
positives on the Approve tab; that's what the approval step is for. Results: `eval/EVALUATION.md`.

## 9. The same from the command line

```powershell
.venv\Scripts\python -m scra.cli review data\samples\mixed_vuln.js
.venv\Scripts\python -m scra.cli review data\samples\package_vuln.json --offline --json
.venv\Scripts\python -m scra.cli stats
.venv\Scripts\python eval\evaluate.py --demo        # the 10 end-to-end demo cases
```
