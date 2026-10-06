import pytest

from scra.tools.inputs import MAX_BYTES, InputError, parse_input


def test_js_file(sample):
    p = parse_input("xss_dom_vuln.js", sample("xss_dom_vuln.js"))
    assert p.kind == "file" and p.files[0].added_lines is None


def test_diff_maps_added_lines_to_new_file(sample):
    p = parse_input("xss_added.diff", sample("xss_added.diff"))
    assert p.kind == "diff"
    f = p.files[0]
    assert f.path == "public/comments.js"
    assert f.added_lines == {6}
    assert "innerHTML" in f.text.splitlines()[5]
    assert "textContent" not in f.text  # removed lines are not in the new file


def test_diff_detected_without_extension():
    text = "--- a/x.js\n+++ b/x.js\n@@ -1,1 +1,2 @@\n const a = 1;\n+eval(a);\n"
    p = parse_input("pasted.txt", text)
    assert p.kind == "diff" and p.files[0].added_lines == {2}


def test_diff_ignores_non_js_files():
    text = "--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hi\n+there\n"
    with pytest.raises(InputError, match="no added lines in JavaScript"):
        parse_input("change.diff", text)


def test_manifest(sample):
    p = parse_input("package.json", sample("package_vuln.json"))
    assert p.kind == "manifest" and "lodash" in p.manifest["dependencies"]


@pytest.mark.parametrize("name,raw,msg", [
    ("a.js", b"", "empty"),
    ("a.js", b"   \n ", "empty"),
    ("a.js", b"\x00\x01\x02bin", "binary"),
    ("a.js", b"\xff\xfe\xfa", "UTF-8"),
    ("a.py", b"print(1)", "Unsupported"),
    ("package.json", b"{not json", "not valid JSON"),
    ("package.json", b"[1, 2]", "JSON object"),
])
def test_invalid_inputs(name, raw, msg):
    with pytest.raises(InputError, match=msg):
        parse_input(name, raw)


def test_oversized_input():
    with pytest.raises(InputError, match="limit"):
        parse_input("big.js", b"a" * (MAX_BYTES + 1))
