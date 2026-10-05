from main.shell import redact


def test_masks_authorization():
    out = redact("Authorization: Bearer abcdefghijklmnop1234")
    assert "abcdefghijklmnop1234" not in out


def test_masks_cookie():
    out = redact("Cookie: session=verysecrettoken123")
    assert "verysecrettoken123" not in out


def test_masks_api_key():
    out = redact("api_key=abcdefghijklmnop")
    assert "abcdefghijklmnop" not in out
