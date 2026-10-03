from apex_fuzzer.discovery.url_normalizer import normalize_url, \
    extract_query_params


def test_lowercases_host():
    assert "EXAMPLE.COM" not in normalize_url("http://EXAMPLE.COM/")


def test_strips_default_http_port():
    assert ":80" not in normalize_url("http://example.com:80/a")


def test_keeps_nondefault_port():
    assert ":8443" in normalize_url("https://example.com:8443/a")


def test_drops_trailing_slash():
    assert normalize_url("http://a.com/x/") == "http://a.com/x"


def test_sorts_query_params():
    a = normalize_url("http://a.com/x?b=2&a=1")
    b = normalize_url("http://a.com/x?a=1&b=2")
    assert a == b


def test_preserves_duplicate_params():
    q = extract_query_params("http://a.com/?x=1&x=2")
    assert q == [("x", "1"), ("x", "2")]


def test_strips_fragment():
    assert "#" not in normalize_url("http://a.com/x#frag")
