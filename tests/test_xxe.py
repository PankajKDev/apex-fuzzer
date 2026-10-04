"""XXE validator tests use local HTTP/OAST fixtures; no network is used."""
import re
from urllib.parse import urlsplit

import pytest

from apex_fuzzer.budgets import BudgetExceeded
from apex_fuzzer.config import Config
from apex_fuzzer.models import Endpoint, Finding
from apex_fuzzer.orchestrator import _classify_finding
from apex_fuzzer.plugins.adapters import _xxe_candidate_from
from apex_fuzzer.plugins.base import TestTarget
from apex_fuzzer.validation.base import Candidate
from apex_fuzzer.validation.xxe import XxeValidator


class Response:
    status_code = 400
    text = "XML parser rejected the document"


class OastFixture:
    def __init__(self, match=True):
        self.match = match
        self.callback = ""
        self.poll_calls = []

    def available(self):
        return True

    def create_token(self):
        return "fixture.oast.test"

    def correlation_key(self, callback):
        return (urlsplit(callback).hostname or "").split(".", 1)[0]

    def poll(self, **kwargs):
        self.poll_calls.append(kwargs)
        value = self.callback if self.match else "unrelated-callback"
        return [{"full-id": value, "proto": "http"}]


class XmlParserFixture:
    def __init__(self, provider):
        self.provider = provider
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        body = kwargs["data"]
        match = re.search(r'SYSTEM "(https?://[^\"]+)"', body)
        if match:
            callback = match.group(1)
            self.provider.callback = self.provider.correlation_key(callback)
        return Response()


def candidate(body="<root><name>sample</name></root>",
              content_type="application/xml"):
    finding = Finding(id="xxe-fixture", source="fixture", name="XXE lead",
                      method="POST", request_body=body)
    return Candidate(
        finding=finding, test_class="xxe",
        endpoint_url="https://app.example.test/import", method="POST",
        request_body=body, request_content_type=content_type)


def run(body="<root><name>sample</name></root>",
        provider_match=True, allow_state_change=True,
        content_type="application/xml"):
    cfg = Config()
    cfg.safety.allow_state_change = allow_state_change
    provider = OastFixture(match=provider_match)
    http = XmlParserFixture(provider)
    result = XxeValidator(cfg, http, provider, timeout=3).validate(
        candidate(body, content_type))
    return result, http, provider


def test_confirms_only_nonce_correlated_external_entity_callback():
    outcome, http, provider = run()

    assert outcome.status == "confirmed"
    assert outcome.evidence["interaction_protocols"] == ["http"]
    assert outcome.evidence["request_count"] == 1
    assert len(http.calls) == 1
    method, _, kwargs = http.calls[0]
    assert method == "POST"
    assert "<!DOCTYPE root" in kwargs["data"]
    assert "file://" not in kwargs["data"]
    assert "SYSTEM \"http://" in kwargs["data"]
    assert provider.poll_calls == [{"timeout": Config().oast.poll_timeout,
                                    "interval": Config().oast.poll_interval}]


def test_unrelated_callback_does_not_confirm():
    outcome, http, _ = run(provider_match=False)

    assert outcome.status == "inconclusive"
    assert "no nonce-correlated" in outcome.notes
    assert len(http.calls) == 1


def test_state_change_gate_and_observed_xml_are_required():
    outcome, http, _ = run(allow_state_change=False)
    assert outcome.status == "inconclusive"
    assert http.calls == []

    outcome, http, _ = run(content_type="application/json")
    assert outcome.status == "inconclusive"
    assert http.calls == []


@pytest.mark.parametrize("body", [
    "", "not xml", "<root><x></root>",
    '<!DOCTYPE root [<!ENTITY old SYSTEM "file:///etc/passwd">]>'
    "<root>&old;</root>",
])
def test_invalid_or_preexisting_dtd_body_is_not_sent(body):
    outcome, http, _ = run(body=body)
    assert outcome.status == "inconclusive"
    assert http.calls == []


def test_body_size_is_bounded():
    outcome, http, _ = run(body="<root>" + "x" * (64 * 1024) + "</root>")
    assert outcome.status == "inconclusive"
    assert "64 KiB" in outcome.notes
    assert http.calls == []


def test_budget_exhaustion_propagates():
    class Exhausted:
        def request(self, *_args, **_kwargs):
            raise BudgetExceeded("fixture request cap")

    cfg = Config()
    cfg.safety.allow_state_change = True
    with pytest.raises(BudgetExceeded):
        XxeValidator(cfg, Exhausted(), OastFixture()).validate(candidate())


def test_adapter_extracts_observed_xml_request_method_body_and_content_type():
    finding = Finding(
        id="xxe-raw", source="nuclei", method="HTTP",
        raw={"request": ("POST /import HTTP/1.1\r\n"
                         "Content-Type: application/xml\r\n"
                         "Authorization: secret\r\n\r\n"
                         "<root><name>sample</name></root>")})
    endpoint = Endpoint(
        url="https://app.example.test/import",
        normalized_url="https://app.example.test/import",
        method="GET", request_content_types=["application/json"])
    target = TestTarget(
        endpoint.url, method="HTTP", finding=finding, endpoint=endpoint,
        test_class="xxe")

    result = _xxe_candidate_from(target)

    assert result.method == "POST"
    assert result.request_content_type == "application/xml"
    assert result.request_body == "<root><name>sample</name></root>"
    assert "Authorization" not in result.request_headers


@pytest.mark.parametrize(("name", "expected"), [
    ("XML External Entity Injection", "xxe"),
    ("XXE in SOAP API", "xxe"),
    ("Local File Inclusion", "path_traversal"),
    ("Directory Traversal", "path_traversal"),
    ("Server-Side Template Injection", "ssti"),
])
def test_finding_names_route_to_class_validators(name, expected):
    assert _classify_finding(Finding(id="classification", source="fixture",
                                     name=name)) == expected


SVG = ('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
       '<rect width="1" height="1"/></svg>')
SOAP = ('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body><GetUser><id>7</id></GetUser></soap:Body></soap:Envelope>')
XMP = ('<x:xmpmeta xmlns:x="adobe:ns:meta/">'
       '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
       '<rdf:Description rdf:about=""/></rdf:RDF></x:xmpmeta>')


def test_svg_body_probed_with_callback():
    from apex_fuzzer.validation.xxe import sniff_xml_shape
    assert sniff_xml_shape(SVG, "image/svg+xml") == "xml"
    result, http, _ = run(SVG, content_type="image/svg+xml")
    assert result.status == "confirmed"
    assert http.calls and http.calls[0][0] == "POST"


def test_soap_namespaced_body_probed_with_callback():
    result, _, _ = run(SOAP, content_type="application/soap+xml")
    assert result.status == "confirmed"


def test_sniffed_svg_without_xml_content_type():
    from apex_fuzzer.validation.xxe import sniff_xml_shape
    assert sniff_xml_shape(SVG, "application/octet-stream") == "xml"
    assert sniff_xml_shape("<?xml version='1.0'?><r/>",
                           "text/plain") == "xml"
    result, _, _ = run(SVG, content_type="application/octet-stream")
    assert result.status == "confirmed"


def test_office_containers_fail_closed_with_note():
    from apex_fuzzer.validation.xxe import sniff_xml_shape, container_note
    assert sniff_xml_shape(b"\x50\x4b\x03\x04docx", "application/vnd.x") == \
        "container"
    assert "isolated" in container_note(b"\x50\x4b\x03\x04x")
    docx = Candidate(
        finding=Finding(id="xxe-docx", source="fixture", method="POST",
                        request_body=b"\x50\x4b\x03\x04docx"),
        test_class="xxe", endpoint_url="https://app.example.test/import",
        method="POST", request_body=b"\x50\x4b\x03\x04docx",
        request_content_type="application/vnd.x")
    cfg = Config()
    cfg.safety.allow_state_change = True
    result = XxeValidator(cfg, XmlParserFixture(OastFixture()),
                          OastFixture(), timeout=3).validate(docx)
    assert result.status == "inconclusive"
    assert "isolated" in result.notes


def test_html_and_json_are_not_xml():
    from apex_fuzzer.validation.xxe import sniff_xml_shape
    assert sniff_xml_shape("<html><body>hi</body></html>",
                           "text/html") == "other"
    assert sniff_xml_shape('{"a": 1}', "application/json") == "other"
    assert sniff_xml_shape("", "text/plain") == "other"
    # XMP metadata text is XML and stays probeable
    assert sniff_xml_shape(XMP, "application/rdf+xml") == "xml"


def test_bom_prefixed_xml_is_sniffed():
    from apex_fuzzer.validation.xxe import sniff_xml_shape
    assert sniff_xml_shape('\ufeff<?xml version="1.0"?><r/>',
                           "text/plain") == "xml"
    assert sniff_xml_shape('\ufeff<svg/>', "text/plain") == "xml"
