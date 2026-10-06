import json

from scra.tools import check_dependencies, parse_input, retrieve_guidance, run_semgrep
from scra.tools.deps import parse_version


def _hits(sample, name):
    return run_semgrep(parse_input(name, sample(name)).files)


def test_semgrep_flags_vulnerable_and_not_fixed(sample):
    vuln = _hits(sample, "sqli_vuln.js")
    assert [(h["vuln_class"], h["cwe"], h["line"]) for h in vuln] == [("injection", "CWE-89", 7)]
    assert _hits(sample, "sqli_fixed.js") == []


def test_semgrep_masks_secrets(sample):
    hits = _hits(sample, "secret_vuln.js")
    assert len(hits) == 3
    joined = " ".join(h["snippet"] for h in hits)
    assert "AKIAIOSFODNN7EXAMPLE" not in joined and "super-secret" not in joined


def test_semgrep_does_not_mask_non_secret_snippets(sample):
    hits = _hits(sample, "xss_reflected_vuln.js")
    assert "<h1>Results for" in hits[0]["snippet"]


def test_semgrep_diff_only_reports_added_lines():
    diff = ("--- a/x.js\n+++ b/x.js\n@@ -1,2 +1,3 @@\n"
            " el.innerHTML = userA;\n el.innerHTML = userB;\n+el.innerHTML = userC;\n")
    hits = run_semgrep(parse_input("x.diff", diff).files)
    assert [h["line"] for h in hits] == [3]


def test_regex_exec_is_not_command_injection():
    code = "const m = /a(b)/.exec(input);\nconst r = pattern.exec(text);\n"
    assert run_semgrep(parse_input("r.js", code).files) == []


def test_parse_version():
    assert parse_version("^4.17.15") == (4, 17, 15)
    assert parse_version("~1.2") == (1, 2, 0)
    assert parse_version("latest") is None


def test_dependencies_snapshot(sample):
    vuln = check_dependencies(json.loads(sample("package_vuln.json")), offline=True)
    assert vuln["source"] == "snapshot"
    assert {v["package"] for v in vuln["vulnerabilities"]} == {"express", "lodash", "jsonwebtoken", "minimist"}
    safe = check_dependencies(json.loads(sample("package_safe.json")), offline=True)
    assert safe["vulnerabilities"] == []


def test_dependencies_falls_back_when_osv_unreachable(monkeypatch, sample):
    import requests
    from scra.tools import deps

    def boom(*a, **k):
        raise requests.ConnectionError("no network")

    monkeypatch.setattr(deps.requests, "post", boom)
    res = check_dependencies(json.loads(sample("package_vuln.json")), offline=False)
    assert res["source"] == "snapshot" and "unreachable" in res["note"]
    assert len(res["vulnerabilities"]) == 4


def test_dependencies_ignores_unpinned():
    res = check_dependencies({"dependencies": {"a": "latest", "b": "git+https://x/y.git"}}, offline=True)
    assert res["checked"] == 0


def test_retrieval_pins_cwe_and_stays_on_topic():
    res = retrieve_guidance("anything at all", vuln_class="insecure_cookie", cwe="CWE-1004")
    assert res[0]["id"] == "CWE-1004"
    assert all(r["id"] in {"CWE-1004", "CWE-614", "OWASP-CS-SESSION"} for r in res)


def test_redaction_preserves_line_numbers():
    from scra.tools.semgrep_tool import redact_secrets_in_code

    src = ('const a = 1;\nconst API_KEY = "abcd1234efgh5678";\n'
           '-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nxyz\n-----END RSA PRIVATE KEY-----\nconst b = 2;\n')
    out = redact_secrets_in_code(src)
    assert out.count("\n") == src.count("\n")
    assert "abcd1234efgh5678" not in out and "MIIEow" not in out
    assert out.splitlines()[-1] == "const b = 2;"


def test_dependencies_skip_aliases():
    res = check_dependencies({"dependencies": {"my-lodash": "npm:lodash@4.17.15"}}, offline=True)
    assert res["checked"] == 0
