from apex_fuzzer.discovery import parameters as p


def test_from_url_basic():
    out = p.from_url("http://a.com/?x=1&y=2")
    names = {q.name for q in out}
    assert names == {"x", "y"}


def test_from_html_input():
    html = '<form><input name="user"><input name="pass"></form>'
    names = {q.name for q in p.from_html(html)}
    assert names == {"user", "pass"}


def test_from_html_hidden():
    html = '<input type="hidden" name="csrf">'
    out = p.from_html(html)
    assert any(q.name == "csrf" for q in out)


def test_from_js_fetch():
    js = "fetch('/api/users?id=42')"
    names = {q.name for q in p.from_js(js)}
    assert "id" in names
