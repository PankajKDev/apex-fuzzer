"""Web-cache deception under the unique-key contract.

Fake cache implementations only. No network.
"""
from types import SimpleNamespace

from main.budgets import BudgetExceeded
from main.safety.preflight import plan_cache
from main.validation.cache import (
    BUSTER_PREFIX, cache_hit_detail, probe_deception)


def _resp(status, text, headers=None):
    return SimpleNamespace(status_code=status, text=text,
                           headers=headers or {})


class _DeceivedCache:
    """URL-keyed cache: anonymous re-read gets the victim body with HIT."""

    def __init__(self):
        self.store = {}
        self.keys = []

    def get(self, url, **kwargs):
        self.keys.append(url)
        assert BUSTER_PREFIX in url, "probes must use unique keys"
        cookie = (kwargs.get("headers") or {}).get("Cookie", "")
        # URL-only cache key: whoever fetched last wins the entry;
        # the fetcher always sees their own origin response
        is_victim = "victim" in cookie
        body = ('{"id": 9, "email": "victim@example.test"}'
                if is_victim else '{"id": 0, "public": true}')
        if url in self.store and not is_victim:
            stored, _ = self.store[url]
            return _resp(200, stored, {"Age": "42"})
        self.store[url] = (body, cookie)
        return _resp(200, body, {})


class _HonestCache:
    """Keyed correctly per identity: anonymous always sees public."""

    def get(self, url, **kwargs):
        cookie = (kwargs.get("headers") or {}).get("Cookie", "")
        if "victim" in cookie:
            return _resp(200, '{"id": 9, "email": "victim@example.test"}')
        return _resp(200, '{"id": 0, "public": true}', {"Age": "7"})


class _PublicCache:
    """Same body for everyone: nothing personalized to leak."""

    def get(self, url, **kwargs):
        return _resp(200, '{"id": 0, "public": true}', {"Age": "7"})


def test_deception_confirmed_on_hit_with_victim_body():
    http = _DeceivedCache()
    res = probe_deception(http, "https://example.test/account",
                          {"Cookie": "s=victim"}, "user_a")
    assert res.verdict == "confirmed"
    assert "Age: 42" in res.hit_detail
    assert len({url for url in http.keys}) == 1  # one unique key reused


def test_correct_keying_is_a_genuine_negative():
    res = probe_deception(_HonestCache(), "https://example.test/account",
                          {"Cookie": "s=victim"}, "user_a")
    assert res.verdict == "tested_negative"


def test_public_content_is_a_genuine_negative():
    res = probe_deception(_PublicCache(), "https://example.test/news",
                          {"Cookie": "s=victim"}, "user_a")
    assert res.verdict == "tested_negative"


def test_errors_are_inconclusive():
    class Http:
        def get(self, *args, **kwargs):
            return _resp(500, "boom")

    res = probe_deception(Http(), "https://example.test/account",
                          {"Cookie": "s=victim"}, "user_a")
    assert res.verdict == "inconclusive"


def test_budget_exhaustion_propagates():
    class Http:
        def get(self, *args, **kwargs):
            raise BudgetExceeded("budget exhausted")

    try:
        probe_deception(Http(), "https://example.test/account", {},
                        "user_a")
    except BudgetExceeded:
        return
    raise AssertionError("BudgetExceeded must propagate")


def test_hit_signals():
    assert cache_hit_detail({"Age": "12"}) == "Age: 12"
    assert cache_hit_detail({"Age": "0"}) == ""
    assert cache_hit_detail({"X-Cache": "HIT"}) != ""
    assert cache_hit_detail({"CF-Cache-Status": "Hit"}) != ""
    assert cache_hit_detail({"X-Cache": "MISS"}) == ""
    assert cache_hit_detail({}) == ""
    assert cache_hit_detail(None) == ""


def test_plan_cache_math():
    assert plan_cache(4).total == 12


def test_hit_detection_accepts_response_header_mappings():
    from collections.abc import Mapping

    class HeaderMap(Mapping):
        def __init__(self, data):
            self._data = dict(data)

        def __getitem__(self, key):
            return self._data[key]

        def __iter__(self):
            return iter(self._data)

        def __len__(self):
            return len(self._data)

    # requests' CaseInsensitiveDict is a Mapping, not a dict
    assert cache_hit_detail(HeaderMap({"Age": "42"})) == "Age: 42"
    assert cache_hit_detail(HeaderMap({"X-Cache": "HIT"})) != ""


def test_hit_multi_value_and_rfc9211_headers():
    assert cache_hit_detail({"X-Cache": "HIT, HIT"}) != ""
    assert cache_hit_detail({"X-Cache": "MISS, HIT from child"}) != ""
    assert cache_hit_detail(
        {"Cache-Status": '"cdn"; hit; ttl=10'}) != ""
    assert cache_hit_detail({"X-Cache": "MISS, MISS"}) == ""
