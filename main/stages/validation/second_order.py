"""Stored-XSS / stored-SSRF correlation probes (opt-in, persist data)."""
from typing import List
from urllib.parse import urlsplit

from ...budgets import BudgetExceeded, BudgetTracker
from ...logging_setup import get_logger
from ...models import (Confidence, Endpoint, Finding, ValidationStatus,
                       stable_finding_id)
from ...reporting.coverage import CoverageTracker
from ...reporting.metrics import Metrics
from ...safety.gate import ScopeRefused
from ...safety.preflight import plan_second_order, plan_second_order_ssrf
from ...validation.evidence import EvidenceStore, interaction_line
from ...validation.oast import matching_interactions
from ...validation.second_order import (find_renders, inject_canary,
                                        make_ssrf_canary,
                                        second_order_ssrf_candidates)
from . import ProbeControls, reserve_or_block
from ...validation.ssrf_triggers import (
    append_query_parameter, assign_nested,
    materialize_trigger_urls, nested_parameter_object,
    rank_ssrf_triggers)

log = get_logger("stages-validation")


def second_order_probe(endpoints: List[Endpoint],
                       evidence: EvidenceStore, metrics: Metrics,
                       budgets: BudgetTracker,
                       coverage: CoverageTracker, client,
                       cfg, scope, controls: ProbeControls,
                       identities) -> List[Finding]:
    cfg_v = cfg.validation
    forms = [e for e in endpoints
             if e.body_parameters
             and scope.active_test_allowed(e.url)]
    forms = forms[:cfg_v.second_order_max_endpoints]
    renders = []
    for e in endpoints:
        if e.endpoint_type == "page" and \
                scope.is_in_scope(e.url) and \
                e.url not in renders:
            renders.append(e.url)
    renders = renders[:cfg_v.second_order_max_renders]
    if not forms or not renders:
        coverage.record("second_order", "untestable",
                        "no HTML forms or render candidates")
        return []
    injectors = [i for i in identities if i.name != "anonymous"] or \
        identities[:1]
    log.info("second-order: %d forms × %d renders as %s",
             len(forms), len(renders),
             [i.name for i in injectors[:1]])
    if not reserve_or_block(
            budgets, coverage, "second_order",
            plan_second_order(len(forms), len(renders))):
        return []
    findings: List[Finding] = []
    for ep in forms:
        if controls.halted():
            log.info("second-order: halted by stop control; "
                     "remaining targets stay untested")
            break
        controls.paced()
        inj = injectors[0]
        iname = getattr(inj, "name", "anonymous")
        iheaders = dict(getattr(inj, "auth_headers", None) or {})
        if not budgets.consume_test("second_order",
                                    ep.normalized_url):
            coverage.record("second_order", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        try:
            inj_res = inject_canary(client, ep, iheaders, iname,
                                    timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("second_order", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        metrics.second_order_tests += 1
        if not inj_res.fields:
            continue
        try:
            hits = find_renders(client, renders + [ep.url],
                                inj_res.canary, ep.url,
                                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("second_order", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        dangerous = [h for h in hits
                     if h.context.startswith("dangerous:")]
        if dangerous:
            h = dangerous[0]
            metrics.second_order_candidates += 1
            controls.noted()
            coverage.record("second_order", "candidate",
                            f"{h.context} at {h.render_url}")
            f = Finding(
                id=stable_finding_id("so", ep.normalized_url, h.render_url),
                source="second-order",
                name=(f"Stored XSS candidate: canary from "
                      f"{ep.path} renders {h.context} at "
                      f"{h.render_url}"),
                severity="high",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.STRONG_CANDIDATE.value,
                host=ep.host, matched_at=h.render_url,
                endpoint_url=h.render_url, method="GET",
                description=(
                    f"Canary {inj_res.canary} injected via POST "
                    f"{ep.url} (fields: "
                    f"{', '.join(inj_res.fields)}) renders "
                    f"{h.detail} at {h.render_url}."),
                tags=["stored-xss", "second-order", "xss"],
                raw={"inject": inj_res.to_dict(),
                     "render": h.to_dict()},
                false_positive_notes=(
                    "Inert unknown tag proves unescaped persistence; "
                    "confirm script execution with a benign payload "
                    "in a private session before reporting."),
                identity=iname,
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"POST {ep.url} "
                              f"(fields: {inj_res.fields})\n"
                              f"canary: {inj_res.canary}"),
                response_text=(f"{h.detail}\n--- snippet ---\n"
                               f"{h.snippet[:1500]}"))
            findings.append(f)
            log.info("second-order: STORED XSS at %s (%s)",
                     h.render_url, h.context)
        elif hits:
            coverage.record("second_order", "tested_negative",
                            f"{ep.normalized_url}: canary encoded")
        else:
            coverage.record("second_order", "inconclusive",
                            f"{ep.normalized_url}: no render observed")
    return findings


def second_order_ssrf_probe(endpoints: List[Endpoint],
                            evidence: EvidenceStore, metrics: Metrics,
                            budgets: BudgetTracker,
                            coverage: CoverageTracker, client,
                            cfg, scope, controls: ProbeControls,
                            identities, provider) -> List[Finding]:
    """Inject unique OAST URLs into URL-like fields and correlate later
    callbacks after in-scope render/worker trigger requests.

    This is separately opt-in because injections persist a callback URL.
    A missing callback is inconclusive: asynchronous processing and
    worker schedules make silence insufficient to prove a negative.
    """
    cfg_v = cfg.validation
    if provider is None or not provider.available():
        coverage.record("second_order_ssrf", "untestable",
                        "OAST provider unavailable")
        return []

    sinks = []
    endpoint_count = 0
    max_endpoints = max(0, cfg_v.second_order_max_endpoints)
    max_fields = max(0, cfg_v.second_order_ssrf_max_fields)
    for ep in endpoints:
        if (endpoint_count >= max_endpoints or
                ep.method.upper() not in ("POST", "PUT", "PATCH") or
                not scope.active_test_allowed(ep.url)):
            continue
        fields = second_order_ssrf_candidates(ep, max_fields)
        if not fields:
            continue
        endpoint_count += 1
        sinks.extend((ep, *candidate) for candidate in fields)
    if not sinks:
        coverage.record("second_order_ssrf", "untestable",
                        "no in-scope URL-like body fields found")
        return []

    trigger_scores = {}
    for sink_ep, *_ in sinks:
        for trigger_ep, score, rationale in rank_ssrf_triggers(
                sink_ep, endpoints):
            if scope.is_in_scope(trigger_ep.url):
                prev = trigger_scores.get(trigger_ep.url)
                if prev is None or score > prev[0]:
                    trigger_scores[trigger_ep.url] = (score, rationale)
    trigger_cap = max(0, cfg_v.second_order_max_renders)
    triggers = [url for url, _ in sorted(
        trigger_scores.items(), key=lambda row: (-row[1][0], row[0]))
        [:trigger_cap]]
    plan = plan_second_order_ssrf(len(sinks), len(triggers))
    if not reserve_or_block(
            budgets, coverage, "second_order_ssrf", plan):
        return []

    actors = [i for i in identities
              if getattr(i, "name", "anonymous") != "anonymous"] \
        or list(identities or [])[:1]
    actor = actors[0] if actors else None
    identity = getattr(actor, "name", "anonymous")
    headers = dict(getattr(actor, "auth_headers", None) or {})
    submitted = []
    budget_blocked = False
    incomplete = False
    for ep, location, parameter, candidate_score, rationale in sinks:
        if controls.halted():
            incomplete = True
            break
        if not budgets.consume_test(
                "second_order_ssrf", ep.normalized_url,
                limit=max_fields):
            coverage.record("second_order_ssrf", "blocked",
                            f"test budget: {ep.normalized_url}")
            budget_blocked = True
            continue
        callback_url = make_ssrf_canary(provider.create_token())
        callback_host = urlsplit(callback_url).hostname or ""
        key_builder = getattr(provider, "correlation_key", None)
        callback_key = (key_builder(callback_url)
                        if callable(key_builder) else callback_host)
        headers_for_request = dict(headers)
        data = {p.name: (p.sample_value or "test")
                for p in ep.body_parameters if p.name}
        json_body = nested_parameter_object(data)
        request_url = ep.url
        if location == "body":
            data[parameter.name] = callback_url
            assign_nested(json_body, parameter.name, callback_url)
        elif location == "query":
            request_url = append_query_parameter(
                request_url, parameter.name, callback_url)
        elif location == "header":
            headers_for_request[parameter.name] = callback_url
        try:
            controls.paced()
            method = ep.method.upper()
            request_kwargs = {"headers": headers_for_request,
                              "timeout": cfg.scan.http_timeout}
            is_json = location == "body" and any(
                "json" in ct.lower() for ct in ep.request_content_types)
            if location == "body":
                request_kwargs["json" if is_json else "data"] = (
                    json_body if is_json else data)
            request_fn = getattr(client, "request", None)
            if callable(request_fn):
                response = request_fn(method, request_url,
                                      **request_kwargs)
            elif method == "POST" and location == "body" and not is_json:
                response = client.post(request_url, **request_kwargs)
            else:
                raise RuntimeError("HTTP client lacks generic request support")
        except ScopeRefused as exc:
            # Gate denial (a BudgetExceeded subclass): the injection
            # never ran — blocked, never incomplete/negative.
            coverage.record("second_order_ssrf", "blocked",
                            f"scope-gate {exc.reason}: "
                            f"{ep.normalized_url}::{parameter.name}")
            budget_blocked = True
            continue
        except BudgetExceeded:
            coverage.record("second_order_ssrf", "blocked",
                            f"budget: {ep.normalized_url}"
                            f"::{parameter.name}")
            budget_blocked = True
            continue
        except Exception as exc:
            log.debug("second-order SSRF injection failed at %s: %s",
                      ep.url, exc)
            incomplete = True
            continue
        if response.status_code >= 400:
            incomplete = True
        metrics.second_order_ssrf_tests += 1
        trigger_urls = materialize_trigger_urls(
            triggers, response, ep.url)
        submitted.append({
            "endpoint": ep, "parameter": parameter.name,
            "location": location,
            "candidate_score": candidate_score,
            "candidate_rationale": rationale,
            "method": method,
            "callback_url": callback_url,
            "callback_host": callback_host,
            "callback_key": callback_key,
            "status": response.status_code,
            "trigger_urls": trigger_urls,
        })

    submitted_triggers = list(dict.fromkeys(
        url for item in submitted for url in item["trigger_urls"]))
    # token reflection in trigger bodies is a non-upgrading readback
    # signal: it shows processed content came back, not just a fetch
    trigger_reflects: dict = {}
    for trigger_url in submitted_triggers:
        if controls.halted():
            incomplete = True
            break
        if not scope.is_in_scope(trigger_url):
            continue
        try:
            controls.paced()
            response = client.get(
                trigger_url, headers=headers,
                timeout=cfg.scan.http_timeout)
            if response.status_code >= 400:
                incomplete = True
            else:
                try:
                    text = response.text or ""
                except Exception:
                    text = ""
                keys = [item["callback_key"] for item in submitted
                        if item["callback_key"] and
                        item["callback_key"] in text]
                if keys:
                    trigger_reflects[trigger_url] = True
        except BudgetExceeded:
            budget_blocked = True
            incomplete = True
            coverage.record("second_order_ssrf", "blocked",
                            f"trigger request budget: {trigger_url}")
            break
        except Exception as exc:
            log.debug("second-order SSRF trigger failed at %s: %s",
                      trigger_url, exc)
            incomplete = True

    interactions = []
    if submitted:
        try:
            interactions = provider.poll(
                timeout=cfg.oast.poll_timeout,
                interval=cfg.oast.poll_interval)
        except Exception as exc:
            log.debug("second-order SSRF OAST polling failed: %s", exc)
            incomplete = True

    findings: List[Finding] = []
    for item in submitted:
        ep = item["endpoint"]
        matched = matching_interactions(
            interactions, item["callback_key"])
        if matched:
            metrics.second_order_ssrf_confirmed += 1
            controls.noted()
            coverage.record(
                "second_order_ssrf", "confirmed",
                f"OAST callback for {ep.normalized_url}"
                f"::{item['parameter']}")
            f = Finding(
                id=stable_finding_id(
                    "second_order_ssrf", ep.normalized_url,
                    item["parameter"]),
                source="second-order-ssrf",
                name=(f"Stored server-side fetch confirmed: {ep.path}"
                      f"::{item['parameter']} triggered an OAST callback"),
                severity="medium",
                confidence=Confidence.CONFIRMED.value,
                validation_status=ValidationStatus.CONFIRMED.value,
                host=ep.host, matched_at=ep.url,
                endpoint_url=ep.url, method=item["method"],
                parameter=item["parameter"],
                description=(
                    f"A unique callback URL stored through {item['method']} "
                    f"{ep.url} in {item['location']} input "
                    f"'{item['parameter']}' received an out-of-band "
                    f"interaction after {len(item['trigger_urls'])} "
                    "related in-scope trigger routes. "
                    "This proves a server-side fetch, but does not by "
                    "itself prove access to internal resources."
                    + (" One or more trigger responses reflect the "
                       "callback token (possible processed-content "
                       "readback: confirm manually)."
                       if any(trigger_reflects.get(url)
                              for url in item["trigger_urls"]) else "")),
                tags=["ssrf", "second-order", "oast",
                      ep.endpoint_type],
                raw={"callback_host": item["callback_host"],
                     "callback_url": item["callback_url"],
                     "trigger_urls": item["trigger_urls"],
                     "trigger_reflects_token": sorted(
                         url for url in item["trigger_urls"]
                         if trigger_reflects.get(url)),
                     "candidate_score": item["candidate_score"],
                     "candidate_rationale": item["candidate_rationale"],
                     "interactions": matched[:10]},
                false_positive_notes=(
                    "A unique DNS/HTTP callback confirms a server-side "
                    "fetch of the injected URL. No internal resources "
                    "were requested or accessed."),
                identity=identity,
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(
                    f"{item['method']} {ep.url}\n{item['location']}"
                    f"::{item['parameter']}="
                    f"{item['callback_url']}\n"
                    + "\n".join(f"GET {url}" for url in
                               item["trigger_urls"])),
                response_text="\n".join(
                    interaction_line(it) for it in matched[:10]))
            findings.append(f)
        else:
            coverage.record(
                "second_order_ssrf",
                "blocked" if budget_blocked else "inconclusive",
                f"no callback observed for {ep.normalized_url}"
                f"::{item['parameter']} after polling")
    if incomplete and not submitted:
        coverage.record("second_order_ssrf", "inconclusive",
                        "injection or trigger flow was incomplete")
    return findings


def blind_xss_probe(endpoints: List[Endpoint],
                    evidence: EvidenceStore, metrics: Metrics,
                    budgets: BudgetTracker,
                    coverage: CoverageTracker, client,
                    cfg, scope, controls: ProbeControls,
                    identities, provider) -> List[Finding]:
    """Correlate stored script-src payloads with OAST callbacks.

    Posts a benign `<script src>` pointing at a unique callback URL
    into every body field, then polls for the fetch. A callback proves
    some client retrieved the URL — not that script executed — so hits
    stay strong candidates for controlled-browser confirmation.
    Silence is inconclusive: admin panels and workers may render later.
    """
    cfg_v = cfg.validation
    if provider is None or not provider.available():
        coverage.record("second_order", "untestable",
                        "OAST provider unavailable for blind-XSS "
                        "correlation")
        return []
    targets = [e for e in endpoints or []
               if (getattr(e, "method", "GET") or "GET").upper()
               in ("POST", "PUT", "PATCH")
               and list(getattr(e, "body_parameters", []) or [])
               and scope.active_test_allowed(e.url)]
    targets = targets[:max(0, cfg_v.second_order_max_endpoints)]
    if not targets:
        coverage.record("second_order", "untestable",
                        "no in-scope mutating endpoints with body fields")
        return []
    if not reserve_or_block(
            budgets, coverage, "second_order",
            plan_second_order(len(targets), 0)):
        return []
    actors = [i for i in identities or []
              if getattr(i, "name", "anonymous") != "anonymous"] \
        or list(identities or [])[:1]
    actor = actors[0] if actors else None
    identity = getattr(actor, "name", "anonymous")
    headers = dict(getattr(actor, "auth_headers", None) or {})
    submitted = []
    budget_blocked = False
    incomplete = False
    for ep in targets:
        if controls.halted():
            incomplete = True
            break
        if not budgets.consume_test("second_order",
                                    ep.normalized_url):
            coverage.record("second_order", "blocked",
                            f"budget: {ep.normalized_url}")
            budget_blocked = True
            continue
        callback_url = make_ssrf_canary(provider.create_token())
        key_builder = getattr(provider, "correlation_key", None)
        callback_key = (key_builder(callback_url)
                        if callable(key_builder)
                        else callback_url)
        fields = [p.name for p in ep.body_parameters if p.name]
        payload = f'<script src="{callback_url}"></script>'
        data = {name: payload for name in fields}
        try:
            controls.paced()
            response = client.post(
                ep.url, data=data, headers=headers,
                timeout=cfg.scan.http_timeout)
        except BudgetExceeded:
            coverage.record("second_order", "blocked",
                            f"budget: {ep.normalized_url}")
            budget_blocked = True
            continue
        except Exception as exc:
            log.debug("blind-XSS injection failed at %s: %s",
                      ep.url, exc)
            incomplete = True
            continue
        metrics.second_order_tests += 1
        submitted.append({
            "endpoint": ep, "fields": fields,
            "callback_url": callback_url,
            "callback_key": callback_key,
            "status": response.status_code,
        })
    interactions = []
    if submitted:
        try:
            interactions = provider.poll(
                timeout=cfg.oast.poll_timeout,
                interval=cfg.oast.poll_interval)
        except Exception as exc:
            log.debug("blind-XSS OAST polling failed: %s", exc)
            incomplete = True
    findings: List[Finding] = []
    for item in submitted:
        ep = item["endpoint"]
        matched = matching_interactions(
            interactions, item["callback_key"])
        if matched:
            metrics.second_order_candidates += 1
            controls.noted()
            coverage.record(
                "second_order", "candidate",
                f"blind-XSS callback for {ep.normalized_url}")
            f = Finding(
                id=stable_finding_id(
                    "blind_xss", ep.normalized_url,
                    item["callback_key"]),
                source="blind-xss",
                name=(f"Blind XSS: stored script payload fetched "
                      f"({ep.path})"),
                severity="medium",
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.
                STRONG_CANDIDATE.value,
                host=ep.host, matched_at=ep.url,
                endpoint_url=ep.url, method="POST",
                description=(
                    f"A unique script-src URL stored through POST "
                    f"{ep.url} (fields: "
                    f"{', '.join(item['fields'])}) received an "
                    f"out-of-band interaction. A client retrieved the "
                    f"payload URL — script execution is NOT proven. "
                    f"Confirm in a controlled browser before reporting."),
                tags=["xss", "blind-xss", "second-order",
                      ep.endpoint_type],
                raw={"callback_url": item["callback_url"],
                     "fields": item["fields"],
                     "interactions": matched[:10]},
                false_positive_notes=(
                    "A DNS/HTTP callback proves a fetch of the injected "
                    "URL, not JavaScript execution (prefetchers, link "
                    "previewers, and scanners also fetch). Replay the "
                    "stored value in an instrumented browser to confirm "
                    "execution."),
                identity=identity,
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(
                    f"POST {ep.url}\n"
                    f"fields {', '.join(item['fields'])} =\n"
                    f"{item['callback_url']} (inside <script src>)"),
                response_text="\n".join(
                    interaction_line(it) for it in matched[:10]))
            findings.append(f)
        else:
            coverage.record(
                "second_order", "blocked" if budget_blocked
                else "inconclusive",
                f"no blind-XSS callback for {ep.normalized_url} "
                f"after polling")
    if incomplete and not submitted:
        coverage.record("second_order", "inconclusive",
                        "blind-XSS injection flow was incomplete")
    return findings


_CLASS_SEVERITY = {"sqli": "high", "cmdi": "high", "ssti": "high",
                   "traversal": "high"}

_CLASS_FP_NOTES = {
    "sqli": "Error text tied to our fresh nonce proves the stored "
            "value reached a database error path. Confirm it is "
            "injectable (not just verbose errors) before reporting.",
    "cmdi": "Shell diagnostics tied to our fresh nonce prove the "
            "stored value reached command execution context. Confirm "
            "with a harmless read-only command before reporting.",
    "ssti": "Paired arithmetic next to our fresh nonce proves server- "
            "side template evaluation. Confirm the engine and context "
            "before reporting.",
    "traversal": "The operator marker contents rendered from a stored "
                 "path proves file readback. Confirm the read path is "
                 "attacker-reachable before reporting.",
}


def second_order_generalized_probe(
        endpoints: List[Endpoint],
        evidence: EvidenceStore, metrics: Metrics,
        budgets: BudgetTracker,
        coverage: CoverageTracker, client,
        cfg, scope, controls: ProbeControls,
        identities) -> List[Finding]:
    """Stored SQLi/CMDi/SSTI/traversal correlation (same opt-in).

    One inert payload per class per form, each correlated by a fresh
    lifecycle nonce; render sweeps are sink-hint ordered. A class
    signal tied to our nonce is a candidate; completed sweeps without
    one are genuine negatives for that error oracle.
    """
    from ...validation.second_order import (
        SECOND_ORDER_SINK_HINTS, classify_stored_signal,
        inject_stored_payload, make_stored_nonce, stored_payloads)
    from ...safety.preflight import plan_second_order_generalized
    cfg_v = cfg.validation
    forms = [e for e in endpoints
             if e.body_parameters
             and scope.active_test_allowed(e.url)]
    forms = forms[:cfg_v.second_order_max_endpoints]
    renders = []
    for e in endpoints:
        if e.endpoint_type == "page" and \
                scope.is_in_scope(e.url) and \
                e.url not in renders:
            renders.append(e.url)
    renders = renders[:cfg_v.second_order_max_renders]
    marker_path = str(getattr(
        cfg_v, "path_traversal_marker_path", "") or "")
    marker_content = str(getattr(
        cfg_v, "path_traversal_marker_content", "") or "")

    def _sink_rank(url: str) -> int:
        try:
            path = urlsplit(url).path.lower()
        except ValueError:
            return 1
        return 0 if any(h in path for h in SECOND_ORDER_SINK_HINTS) \
            else 1

    renders = sorted(renders, key=_sink_rank)
    if not forms or not renders:
        coverage.record("second_order", "untestable",
                        "no HTML forms or render candidates")
        return []
    # Traversal needs the operator marker (8+ content chars); other
    # classes always run under the second-order opt-in.
    n_classes = 3 + (1 if marker_path and len(marker_content) >= 8
                     else 0)
    if not reserve_or_block(
            budgets, coverage, "second_order",
            plan_second_order_generalized(len(forms), len(renders),
                                          n_classes)):
        return []
    injectors = [i for i in identities if i.name != "anonymous"] or \
        identities[:1]
    log.info("second-order-generalized: %d forms × %d renders (%d "
             "classes) as %s", len(forms), len(renders), n_classes,
             [i.name for i in injectors[:1]])
    findings: List[Finding] = []
    for ep in forms:
        if controls.halted():
            log.info("second-order-generalized: halted by stop "
                     "control; remaining targets stay untested")
            break
        controls.paced()
        inj = injectors[0]
        iname = getattr(inj, "name", "anonymous")
        iheaders = dict(getattr(inj, "auth_headers", None) or {})
        if not budgets.consume_test("second_order",
                                    ep.normalized_url):
            coverage.record("second_order", "blocked",
                            f"budget: {ep.normalized_url}")
            continue
        metrics.second_order_tests += 1
        nonce = make_stored_nonce()
        form_blocked = False
        for cls, value in stored_payloads(nonce, marker_path
                                          if len(marker_content) >= 8
                                          else ""):
            if form_blocked:
                break
            try:
                inj_res = inject_stored_payload(
                    client, ep, iheaders, iname, value,
                    timeout=cfg.scan.http_timeout)
            except BudgetExceeded:
                coverage.record("second_order", "blocked",
                                f"budget: {ep.normalized_url}")
                break
            if not inj_res.fields:
                continue
            signal = None
            fetched_any = False
            for url in renders + [ep.url]:
                try:
                    r = client.get(url, timeout=cfg.scan.http_timeout)
                except BudgetExceeded:
                    coverage.record("second_order", "blocked",
                                    f"budget: {ep.normalized_url}")
                    form_blocked = True
                    break
                except Exception as e:
                    log.debug("generalized render fetch %s failed: %s",
                              url, e)
                    continue
                if r.status_code != 200 or not r.text:
                    continue
                fetched_any = True
                state = classify_stored_signal(
                    cls, r.text, nonce, marker_content)
                if state == "signal":
                    signal = (url, r.text)
                    break
            if form_blocked:
                break
            if signal is None:
                coverage.record(
                    "second_order",
                    "tested_negative" if fetched_any else "inconclusive",
                    f"{ep.normalized_url}::{cls}: "
                    f"{'no class signal in completed sweep' if fetched_any else 'no render observed'}")
                continue
            url, text = signal
            metrics.second_order_candidates += 1
            controls.noted()
            coverage.record("second_order", "candidate",
                            f"{ep.normalized_url}::{cls}: class signal "
                            f"at {url}")
            pos = text.find(nonce)
            if pos < 0:
                pos = text.find(marker_content) \
                    if marker_content and marker_content in text else 0
            snippet = text[max(0, pos - 300):pos + 600]
            f = Finding(
                id=stable_finding_id("so", cls, ep.normalized_url,
                                     url),
                source=f"second-order-{cls}",
                name=(f"Stored {cls.upper()} candidate: payload from "
                      f"{ep.path} triggers class signal at "
                      f"{urlsplit(url).path}"),
                severity=_CLASS_SEVERITY.get(cls, "high"),
                confidence=Confidence.PROBABLE.value,
                validation_status=ValidationStatus.
                STRONG_CANDIDATE.value,
                host=ep.host, matched_at=url,
                endpoint_url=url, method="GET",
                parameter=",".join(inj_res.fields[:3]),
                description=(
                    f"Stored {cls} payload (lifecycle {nonce}) injected "
                    f"via POST {ep.url} triggers a class signal at "
                    f"{url}."),
                tags=[f"stored-{cls}", "second-order", cls],
                raw={"inject": inj_res.to_dict(), "class": cls,
                     "nonce": nonce, "render_url": url},
                false_positive_notes=_CLASS_FP_NOTES.get(cls, ""),
                identity=iname,
            )
            evidence.allocate(f)
            evidence.record(
                f,
                request_text=(f"POST {ep.url} "
                              f"(fields: {inj_res.fields})\n"
                              f"class: {cls}; lifecycle: {nonce}"),
                response_text=(f"class signal at {url}\n"
                                f"--- snippet ---\n{snippet[:1500]}"))
            findings.append(f)
            log.info("second-order-generalized: STORED %s at %s",
                     cls.upper(), url)
    return findings
