"""Deterministic text used by the mock provider and as a fallback when an LLM omits a tool hit."""

TITLE_TEMPLATES = {
    "xss": "Cross-site scripting: unencoded data written to HTML (line {line})",
    "injection": "Injection: untrusted input reaches a code/command/query interpreter (line {line})",
    "insecure_cookie": "Cookie set without httpOnly/secure flags (line {line})",
    "missing_input_validation": "Request body used without schema validation (line {line})",
    "hardcoded_secret": "Hardcoded credential in source (line {line})",
    "vulnerable_dependency": "Vulnerable dependency: {package}@{version} ({advisory})",
}

FIX_TEMPLATES = {
    "xss": "Encode the value for its HTML context before writing it (e.g. escape-html on the server), "
           "or use textContent / createElement instead of innerHTML in the browser. If HTML must be "
           "allowed, sanitize it with DOMPurify.",
    "injection": "Do not build interpreter input from strings. Use parameterized queries "
                 "(db.query('... WHERE id = ?', [id])), execFile/spawn with an argument array instead of "
                 "exec, and JSON.parse or a lookup table instead of eval. Validate inputs against an allow-list.",
    "insecure_cookie": "Pass {{ httpOnly: true, secure: true, sameSite: 'strict' }} (or 'lax') as the third "
                       "argument to res.cookie, and configure express-session's cookie block the same way.",
    "missing_input_validation": "Validate req.body against an explicit schema (zod, joi, express-validator), "
                                "return 400 on failure, and pass only the parsed fields to the data layer.",
    "hardcoded_secret": "Remove the literal and read it from an environment variable or secrets manager "
                        "(process.env.NAME), failing fast at startup if it is missing. Treat the exposed "
                        "value as compromised: revoke and rotate it.",
    "vulnerable_dependency": "Upgrade {package} to {fixed} or later, regenerate the lockfile, and re-run tests.",
}

# More specific fixes where one class covers several CWEs.
FIX_BY_CWE = {
    "CWE-89": "Use a parameterized query: keep the SQL text constant and pass values separately, e.g. "
              "db.query('SELECT * FROM products WHERE id = ?', [id]). Parse and range-check numeric ids "
              "before use.",
    "CWE-78": "Avoid the shell: call execFile or spawn with a fixed program name and an argument array, and "
              "validate each argument against a strict allow-list (e.g. net.isIP for a host). Prefer a "
              "library API over shelling out at all.",
    "CWE-95": "Never evaluate request data as code. Use JSON.parse for data, a lookup table of allowed "
              "operations for dispatch, or a dedicated expression parser for calculator-style input.",
    "CWE-1004": FIX_TEMPLATES["insecure_cookie"],
}


def fix_for(vuln_class: str, cwe: str, fields: dict) -> str:
    return FIX_BY_CWE.get(cwe, FIX_TEMPLATES[vuln_class]).format(**fields)


SEVERITY_DEFAULT = {
    "xss": "high",
    "injection": "critical",
    "insecure_cookie": "medium",
    "missing_input_validation": "medium",
    "hardcoded_secret": "high",
    "vulnerable_dependency": "high",
}
