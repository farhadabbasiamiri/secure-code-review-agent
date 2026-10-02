# Safety Boundaries

This is a **defensive** tool. The following boundaries are design requirements, not guidelines.
Each one names where it is enforced and how it is tested.

1. **No code execution.** Uploaded code is parsed and pattern-matched only. It is never
   `require`d, `eval`ed, installed, or run. Semgrep reads a temporary copy.
   *Tested:* binary and unsupported uploads are rejected (`eval/demo_cases.json`).
2. **No exploit generation.** The agent explains *why* code is unsafe and *how to fix it*.
   Prompts instruct the LLM not to produce payloads or attack steps; model text (findings and patch
   drafts) is filtered for payload-like strings before display.
   *Tested:* `test_attack_payloads_are_redacted`, `test_llm_patch_is_masked_and_redacted`, safety eval.
3. **Toy / educational data only.** The dataset is synthetic examples written for this project.
4. **Human approval for sensitive actions.** Drafting PR review comments or a patch requires an
   explicit approval of that finding. The check is in `approval.py`, so it can't be skipped from the
   UI or the API. Nothing is ever posted to a repository or applied to code.
   *Tested:* `test_sensitive_actions_need_approval`, `test_patch_handler_refuses_unapproved`, safety eval.
5. **Secrets handling.** Secret-looking literals are masked (first 4 characters kept) before code
   is sent to the LLM, in every snippet and patch diff, and never reach the logs. API keys are read
   from the environment or held in session memory; they are not written to disk or logs, and are
   masked if a provider's error message echoes them.
   *Tested:* `test_secrets_are_not_sent_to_the_llm`, `test_secret_patch_never_shows_the_secret`,
   `test_server_error_text_is_shown_and_key_is_masked`, safety eval.
6. **Logs hold metadata, not code.** Logs record tool names, timings, counts, classes, decisions and
   errors, never the uploaded source, snippets, or keys. *Tested:* `test_decisions_are_logged_as_metadata`.
7. **Grounded claims.** Every finding must match tool evidence; explanations cite retrieved
   OWASP/CWE entries. Ungrounded findings are dropped by the validator. A failed scanner is reported
   as an incomplete review, never as a clean one.
8. **Untrusted input in the prompt.** The model is told the code is data. Instructions inside it
   (comments, strings) can't remove a tool finding. *Tested:* `test_instructions_in_code_do_not_suppress_findings`.
9. **No server-side request forgery on public deployments.** With `SCRA_HOSTED=1`, visitors can only
   choose fixed hosted LLM endpoints; local presets and custom URLs are disabled and ignored by the
   backend. *Tested:* `test_hosted_mode_blocks_local_servers`.
10. **Rendered output is escaped.** Snippets and model text are HTML-escaped in the UI, so a
    malicious upload can't run script in the reviewer's browser. *Tested:* `test_rendered_html_escapes_uploaded_code`.
