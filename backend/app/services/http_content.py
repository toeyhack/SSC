"""Bounded HTTP-content inspection and deterministic SSC-aligned evaluation.

Response bodies and clear contact values are intentionally transient.  The
public observation contains only parse state, counts, hashes, and small
redacted samples needed to reproduce each decision.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree


HTTP_CONTENT_METHOD_VERSION = "ssc-http-content-observation.v1"
HTTP_CONTENT_POLICY_VERSION = "ssc-http-content-policy.v1"
HTTP_CONTENT_ISSUE_KEYS = (
    "unsafe_sri_v2",
    "insecure_ftp",
    "contact_information_detected",
    "local_file_path_exposed_via_url_scheme",
    "server_error",
    "links_to_insecure_website",
    "service_soap",
)

HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}
XML_MEDIA_TYPES = {
    "text/xml", "application/xml", "application/soap+xml",
    "application/wsdl+xml",
}
CONTACT_SCHEMES = {"mailto", "tel", "sms", "whatsapp", "viber"}
URL_ATTRIBUTES = {
    "a": {"href"}, "area": {"href"}, "audio": {"src"}, "embed": {"src"},
    "form": {"action"}, "iframe": {"src"}, "img": {"src"},
    "input": {"src"}, "link": {"href"}, "object": {"data"},
    "script": {"src"}, "source": {"src"}, "track": {"src"},
    "video": {"src", "poster"},
}
SRI_ALGORITHMS = {
    "sha256": (hashlib.sha256, 32),
    "sha384": (hashlib.sha384, 48),
    "sha512": (hashlib.sha512, 64),
}
MAX_REDACTED_SAMPLES = 10
MAX_URL_ATTRIBUTES = 2000
MAX_SRI_CANDIDATES = 100
SOAP_NAMESPACES = {
    "http://schemas.xmlsoap.org/soap/envelope/",
    "http://www.w3.org/2003/05/soap-envelope",
}
WSDL_NAMESPACES = {
    "http://schemas.xmlsoap.org/wsdl/",
    "http://www.w3.org/ns/wsdl",
}
WSDL_SOAP_NAMESPACES = {
    "http://schemas.xmlsoap.org/wsdl/soap/",
    "http://schemas.xmlsoap.org/wsdl/soap12/",
    "http://www.w3.org/ns/wsdl/soap",
}


class _ContentHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.urls: list[tuple[str, str, str, dict[str, str | None]]] = []
        self.attribute_limit_exceeded = False

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.casefold()
        values = {str(name).casefold(): value for name, value in attrs if name}
        if tag == "base" and self.base_href is None and isinstance(values.get("href"), str):
            self.base_href = values["href"]
        for attribute in URL_ATTRIBUTES.get(tag, set()):
            value = values.get(attribute)
            if not isinstance(value, str) or not value.strip():
                continue
            if len(self.urls) >= MAX_URL_ATTRIBUTES:
                self.attribute_limit_exceeded = True
                continue
            self.urls.append((tag, attribute, value.strip(), values))


def inspect_http_content(
    body: bytes,
    content_type: str | None,
    document_url: str,
    *,
    body_complete: bool,
    content_encoding: str | None,
) -> dict[str, Any]:
    """Inspect one bounded response without retaining its body."""
    media_type, charset = _parse_content_type(content_type)
    common: dict[str, Any] = {
        "inspection_status": "INDETERMINATE",
        "reason": None,
        "media_type": media_type,
        "body_complete": body_complete,
        "document_sha256": hashlib.sha256(body).hexdigest(),
    }
    if not body_complete:
        return {**common, "reason": "response_body_truncated"}
    if content_encoding and content_encoding.casefold().strip() not in {"", "identity"}:
        return {**common, "reason": "unsupported_content_encoding"}
    if media_type in HTML_MEDIA_TYPES:
        return {**common, **_inspect_html(body, charset, document_url)}
    if media_type in XML_MEDIA_TYPES or (media_type and media_type.endswith("+xml")):
        return {**common, **_inspect_xml(body)}
    return {**common, "reason": "unsupported_content_type"}


def _inspect_html(body: bytes, charset: str | None, document_url: str) -> dict[str, Any]:
    try:
        text = body.decode(charset or "utf-8", errors="strict")
    except (LookupError, UnicodeDecodeError):
        return {"inspection_status": "INDETERMINATE", "reason": "html_decode_error"}
    if "\x00" in text:
        return {"inspection_status": "INDETERMINATE", "reason": "html_contains_null"}
    parser = _ContentHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        return {"inspection_status": "INDETERMINATE", "reason": "html_parse_error"}
    if parser.rawdata:
        return {"inspection_status": "INDETERMINATE", "reason": "incomplete_html_token"}

    url_parse_error = False
    try:
        effective_base = urljoin(document_url, parser.base_href) if parser.base_href else document_url
        urlparse(effective_base).hostname
    except ValueError:
        effective_base = document_url
        url_parse_error = True
    match_counts = {
        "insecure_ftp": 0,
        "contact_information_detected": 0,
        "local_file_path_exposed_via_url_scheme": 0,
        "links_to_insecure_website": 0,
    }
    samples: dict[str, list[dict[str, Any]]] = {key: [] for key in match_counts}
    sri_candidates: list[dict[str, Any]] = []
    sri_limit_exceeded = False

    for tag, attribute, raw_value, attrs in parser.urls:
        try:
            resolved = urljoin(effective_base, raw_value)
            parsed = urlparse(resolved)
            parsed.hostname
            parsed.port
        except ValueError:
            url_parse_error = True
            continue
        scheme = parsed.scheme.casefold()
        keys: list[str] = []
        if scheme == "ftp":
            keys.append("insecure_ftp")
        if attribute == "href" and scheme in CONTACT_SCHEMES:
            keys.append("contact_information_detected")
        if scheme == "file":
            keys.append("local_file_path_exposed_via_url_scheme")
        if scheme == "http":
            keys.append("links_to_insecure_website")
        for key in keys:
            match_counts[key] += 1
            if len(samples[key]) < MAX_REDACTED_SAMPLES:
                samples[key].append(_redacted_url_sample(tag, attribute, scheme, resolved))

        is_script = tag == "script" and attribute == "src"
        rel_tokens = {token.casefold() for token in str(attrs.get("rel") or "").split()}
        is_stylesheet = tag == "link" and attribute == "href" and "stylesheet" in rel_tokens
        if not (is_script or is_stylesheet):
            continue
        if len(sri_candidates) >= MAX_SRI_CANDIDATES:
            sri_limit_exceeded = True
            continue
        sri_candidates.append(_sri_candidate(
            resolved,
            document_url,
            tag,
            attribute,
            attrs.get("integrity"),
            attrs.get("crossorigin"),
        ))

    return {
        "inspection_status": "COMPLETE" if not parser.attribute_limit_exceeded and not url_parse_error else "INDETERMINATE",
        "reason": (
            "url_attribute_limit_exceeded" if parser.attribute_limit_exceeded
            else "malformed_url_attribute" if url_parse_error else None
        ),
        "content_kind": "HTML",
        "url_attribute_count": len(parser.urls),
        "match_counts": match_counts,
        "match_samples": samples,
        "sri_candidates": sri_candidates,
        "sri_candidate_limit_exceeded": sri_limit_exceeded,
        "soap": {"matched": False, "parse_status": "NOT_XML", "semantic": None},
    }


def _inspect_xml(body: bytes) -> dict[str, Any]:
    try:
        root = ElementTree.fromstring(body)
    except (ElementTree.ParseError, ValueError):
        return {
            "inspection_status": "INDETERMINATE",
            "reason": "xml_parse_error",
            "content_kind": "XML",
            "soap": {"matched": None, "parse_status": "MALFORMED", "semantic": None},
        }
    namespace, local_name = _split_xml_name(root.tag)
    semantic = None
    if local_name == "Envelope" and namespace in SOAP_NAMESPACES:
        semantic = "SOAP_ENVELOPE"
    elif local_name in {"definitions", "description"} and namespace in WSDL_NAMESPACES:
        for element in root.iter():
            child_namespace, child_name = _split_xml_name(element.tag)
            if child_name == "binding" and child_namespace in WSDL_SOAP_NAMESPACES:
                semantic = "WSDL_SOAP_BINDING"
                break
    return {
        "inspection_status": "COMPLETE",
        "reason": None,
        "content_kind": "XML",
        "soap": {
            "matched": semantic is not None,
            "parse_status": "PARSED",
            "semantic": semantic,
            "root_namespace_hash": _hash_text(namespace) if namespace else None,
            "root_local_name": _bounded_xml_name(local_name),
        },
    }


def _split_xml_name(value: Any) -> tuple[str | None, str]:
    if not isinstance(value, str):
        return None, ""
    match = re.fullmatch(r"\{([^}]*)\}(.*)", value)
    return (match.group(1), match.group(2)) if match else (None, value)


def _bounded_xml_name(value: str) -> str:
    if len(value) <= 64 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", value):
        return value
    return "sha256:" + _hash_text(value)


def _parse_content_type(value: str | None) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, None
    parts = [item.strip() for item in value.split(";")]
    media_type = parts[0].casefold()
    charset = None
    for parameter in parts[1:]:
        name, separator, parameter_value = parameter.partition("=")
        if separator and name.strip().casefold() == "charset":
            charset = parameter_value.strip().strip('"\'') or None
            break
    return media_type, charset


def _redacted_url_sample(tag: str, attribute: str, scheme: str, resolved: str) -> dict[str, Any]:
    parsed = urlparse(resolved)
    return {
        "element": tag,
        "attribute": attribute,
        "scheme": scheme,
        "destination_host_hash": _hash_text(parsed.hostname.casefold()) if parsed.hostname else None,
        "destination_path_hash": _hash_text(parsed.path or "/"),
        "destination_value_hash": _hash_text(resolved),
    }


def _sri_candidate(
    resolved: str,
    document_url: str,
    tag: str,
    attribute: str,
    integrity: str | None,
    crossorigin: str | None,
) -> dict[str, Any]:
    parsed = urlparse(resolved)
    if parsed.fragment:
        resolved = parsed._replace(fragment="").geturl()
        parsed = urlparse(resolved)
    document = urlparse(document_url)
    resource_port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80 if parsed.scheme.casefold() == "http" else None)
    document_port = document.port or (443 if document.scheme.casefold() == "https" else 80)
    same_origin = (
        parsed.scheme.casefold() == document.scheme.casefold()
        and (parsed.hostname or "").casefold() == (document.hostname or "").casefold()
        and resource_port == document_port
    )
    digests, metadata_status = _parse_integrity(integrity)
    mode = str(crossorigin).strip().casefold() if crossorigin is not None else None
    if mode in {"", "anonymous"}:
        mode = "anonymous"
    elif mode != "use-credentials" and mode is not None:
        mode = "invalid"
    candidate = {
        "resource_id": _hash_text(resolved),
        "element": tag,
        "attribute": attribute,
        "scheme": parsed.scheme.casefold(),
        "destination_host_hash": _hash_text(parsed.hostname.casefold()) if parsed.hostname else None,
        "destination_path_hash": _hash_text(parsed.path or "/"),
        "same_origin": same_origin,
        "crossorigin_mode": mode,
        "integrity_status": metadata_status,
        "integrity_algorithms": sorted(digests),
        "integrity_token_hashes": sorted(
            _hash_text(f"{algorithm}-{base64.b64encode(value).decode('ascii')}")
            for algorithm, values in digests.items() for value in values
        ),
        "resource_check": None,
        "_fetch_url": resolved,
        "_digests": digests,
    }
    if metadata_status in {"MISSING", "INVALID", "DISALLOWED"}:
        candidate["outcome"] = "MATCH"
        candidate["reason"] = f"integrity_metadata_{metadata_status.casefold()}"
    elif parsed.scheme.casefold() not in {"http", "https"}:
        candidate["outcome"] = "INDETERMINATE"
        candidate["reason"] = "unsupported_resource_scheme"
    elif not same_origin:
        candidate["outcome"] = "INDETERMINATE"
        candidate["reason"] = "cross_origin_resource_not_fetched"
    else:
        candidate["outcome"] = "PENDING"
        candidate["reason"] = "resource_digest_required"
    return candidate


def _parse_integrity(integrity: str | None) -> tuple[dict[str, list[bytes]], str]:
    if not isinstance(integrity, str) or not integrity.strip():
        return {}, "MISSING"
    digests: dict[str, list[bytes]] = {}
    saw_token = False
    saw_unsupported = False
    for token in integrity.split():
        saw_token = True
        value, question, _options = token.partition("?")
        algorithm, separator, encoded = value.partition("-")
        algorithm = algorithm.casefold()
        if not separator or not encoded:
            return {}, "INVALID"
        if algorithm not in SRI_ALGORITHMS:
            saw_unsupported = True
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return {}, "INVALID"
        if len(decoded) != SRI_ALGORITHMS[algorithm][1] or (question and not _options):
            return {}, "INVALID"
        digests.setdefault(algorithm, []).append(decoded)
    if not saw_token:
        return {}, "MISSING"
    if not digests:
        return {}, "DISALLOWED" if saw_unsupported else "INVALID"
    return digests, "VALID"


def complete_sri_candidate(candidate: dict[str, Any], resource_result: dict[str, Any] | None) -> None:
    """Attach a compact digest decision to a same-origin SRI candidate in place."""
    if candidate.get("outcome") != "PENDING":
        return
    if resource_result is None:
        candidate.update(outcome="INDETERMINATE", reason="resource_request_budget_exhausted")
        return
    body = resource_result.get("_body")
    status = resource_result.get("status_code")
    complete = resource_result.get("body_complete") is True
    encodings = resource_result.get("headers", {}).get("content-encoding", [])
    unsupported_encoding = any(str(value).strip().casefold() not in {"", "identity"} for value in encodings)
    if (
        not resource_result.get("endpoint_available")
        or resource_result.get("stop_reason") != "terminal_response"
        or not isinstance(status, int)
        or not 200 <= status <= 299
        or not complete
        or not isinstance(body, bytes)
        or unsupported_encoding
        or resource_result.get("_sri_cross_origin_redirect") is True
    ):
        candidate.update(outcome="INDETERMINATE", reason="resource_fetch_incomplete")
        candidate["resource_check"] = {
            "status_code": status,
            "stop_reason": resource_result.get("stop_reason"),
            "body_complete": complete,
            "unsupported_content_encoding": unsupported_encoding,
            "cross_origin_redirect": resource_result.get("_sri_cross_origin_redirect") is True,
        }
        return
    digests = candidate.get("_digests", {})
    # SRI compares only metadata using the strongest supported algorithm that
    # is present.  Weaker tokens cannot rescue a mismatching stronger token.
    algorithm_priority = {algorithm: index for index, algorithm in enumerate(SRI_ALGORITHMS)}
    strongest_algorithm = max(digests, key=algorithm_priority.__getitem__)
    digest = SRI_ALGORITHMS[strongest_algorithm][0](body).digest()
    matched = any(digest == expected for expected in digests[strongest_algorithm])
    candidate.update(
        outcome="NO_MATCH" if matched else "MATCH",
        reason="permitted_digest_verified" if matched else "all_permitted_digests_mismatched",
    )
    candidate["resource_check"] = {
        "status_code": status,
        "stop_reason": resource_result.get("stop_reason"),
        "body_complete": complete,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "selected_integrity_algorithm": strongest_algorithm,
        "computed_digest_hashes": {
            strongest_algorithm: hashlib.sha256(digest).hexdigest(),
        },
    }


def public_content_observation(content: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(content, dict):
        return None
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if not key.startswith("_")}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return clean(content)


def evaluate_http_content(attempts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    declared = [attempt for attempt in attempts if attempt.get("coverage_declared")]
    groups = _group_declared_endpoints(declared)
    responsive_endpoint_keys = {
        key for key, group in groups.items() if _endpoint_has_http_response(group)
    }
    evaluations: dict[str, dict[str, Any]] = {}
    issue_to_count = {
        "insecure_ftp": "insecure_ftp",
        "contact_information_detected": "contact_information_detected",
        "local_file_path_exposed_via_url_scheme": "local_file_path_exposed_via_url_scheme",
        "links_to_insecure_website": "links_to_insecure_website",
    }
    for issue_key, count_key in issue_to_count.items():
        values, details = [], []
        for attempt in declared:
            state, detail = _content_attempt_state(attempt)
            endpoint_responsive = _endpoint_key(attempt) in responsive_endpoint_keys
            detail["endpoint_responsive"] = endpoint_responsive
            detail["content_evaluation_applicable"] = endpoint_responsive
            if not endpoint_responsive:
                detail["applicability_reason"] = "no_http_response"
                details.append(detail)
                continue
            content = attempt.get("content") if state is not None else None
            if state is not True or not isinstance(content, dict) or content.get("content_kind") != "HTML":
                value = None
            else:
                count = content.get("match_counts", {}).get(count_key)
                value = count > 0 if isinstance(count, int) else None
                detail["match_count"] = count
                detail["samples"] = content.get("match_samples", {}).get(count_key, [])
            values.append(value)
            details.append(detail)
        evaluations[issue_key] = _evaluation(
            _aggregate(values),
            "evaluated URL schemes in completely parsed declared HTML responses",
            details,
        )

    sri_values, sri_details = [], []
    for attempt in declared:
        state, detail = _content_attempt_state(attempt)
        endpoint_responsive = _endpoint_key(attempt) in responsive_endpoint_keys
        detail["endpoint_responsive"] = endpoint_responsive
        detail["content_evaluation_applicable"] = endpoint_responsive
        if not endpoint_responsive:
            detail["applicability_reason"] = "no_http_response"
            sri_details.append(detail)
            continue
        content = attempt.get("content") if state is not None else None
        candidates = content.get("sri_candidates", []) if isinstance(content, dict) else []
        if state is not True or not isinstance(content, dict) or content.get("content_kind") != "HTML":
            value = None
        elif content.get("sri_candidate_limit_exceeded"):
            value = True if any(item.get("outcome") == "MATCH" for item in candidates) else None
        else:
            candidate_values = [
                True if item.get("outcome") == "MATCH" else False if item.get("outcome") == "NO_MATCH" else None
                for item in candidates
            ]
            value = _aggregate(candidate_values) if candidate_values else False
        detail["resource_count"] = len(candidates)
        detail["resources"] = public_content_observation({"items": candidates})["items"]
        sri_values.append(value)
        sri_details.append(detail)
    evaluations["unsafe_sri_v2"] = _evaluation(
        _aggregate(sri_values),
        "evaluated policy-covered script and stylesheet integrity metadata and bounded same-origin resource digests",
        sri_details,
    )

    soap_values, soap_details = [], []
    for attempt in declared:
        state, detail = _content_attempt_state(attempt)
        endpoint_responsive = _endpoint_key(attempt) in responsive_endpoint_keys
        detail["endpoint_responsive"] = endpoint_responsive
        detail["content_evaluation_applicable"] = endpoint_responsive
        if not endpoint_responsive:
            detail["applicability_reason"] = "no_http_response"
            soap_details.append(detail)
            continue
        content = attempt.get("content") if state is not None else None
        soap = content.get("soap") if isinstance(content, dict) else None
        if state is not True or not isinstance(soap, dict):
            value = None
        else:
            value = soap.get("matched") if isinstance(soap.get("matched"), bool) else None
            detail["soap"] = soap
        soap_values.append(value)
        soap_details.append(detail)
    evaluations["service_soap"] = _evaluation(
        _aggregate(soap_values),
        "parsed declared authorized endpoints for a SOAP Envelope or WSDL SOAP binding",
        soap_details,
    )

    server_values, server_details = [], []
    for (scheme, port, path), group in groups.items():
        ordered = sorted(group, key=lambda item: item.get("attempt_number", 0))
        statuses = [item.get("status_code") for item in ordered]
        responsive = _endpoint_has_http_response(ordered)
        complete = len(ordered) == 2 and all(
            item.get("endpoint_available") and item.get("stop_reason") == "terminal_response"
            and isinstance(item.get("status_code"), int)
            for item in ordered
        )
        five_xx = [isinstance(status, int) and 500 <= status <= 599 for status in statuses]
        if not responsive:
            value = None
        elif not complete:
            value = None
        elif all(five_xx):
            value = True
        elif any(five_xx):
            value = None
        else:
            value = False
        if responsive:
            server_values.append(value)
        server_details.append({
            "scheme": scheme, "port": port, "path": path,
            "endpoint_responsive": responsive,
            "server_error_evaluation_applicable": responsive,
            "applicability_reason": None if responsive else "no_http_response",
            "attempts": [
                {
                    "attempt_number": item.get("attempt_number"),
                    "status_code": item.get("status_code"),
                    "stop_reason": item.get("stop_reason"),
                    "response_headers_sha256": item.get("response_headers_sha256"),
                    "observed_at": item.get("observed_at"),
                }
                for item in ordered
            ],
        })
    evaluations["server_error"] = _evaluation(
        _aggregate(server_values),
        "required two bounded safe GET attempts for every declared endpoint",
        server_details,
    )
    return evaluations


def _endpoint_key(attempt: dict[str, Any]) -> tuple[Any, Any, Any]:
    return (
        attempt.get("request_scheme"),
        attempt.get("request_port"),
        attempt.get("request_path"),
    )


def _group_declared_endpoints(
    attempts: list[dict[str, Any]],
) -> dict[tuple[Any, Any, Any], list[dict[str, Any]]]:
    groups: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = {}
    for attempt in attempts:
        groups.setdefault(_endpoint_key(attempt), []).append(attempt)
    return groups


def _endpoint_has_http_response(attempts: list[dict[str, Any]]) -> bool:
    return any(isinstance(attempt.get("status_code"), int) for attempt in attempts)


def _content_attempt_state(attempt: dict[str, Any]) -> tuple[bool | None, dict[str, Any]]:
    content = attempt.get("content")
    detail = {
        "scheme": attempt.get("request_scheme"),
        "port": attempt.get("request_port"),
        "path": attempt.get("request_path"),
        "attempt_number": attempt.get("attempt_number"),
        "status_code": attempt.get("status_code"),
        "stop_reason": attempt.get("stop_reason"),
        "content_type": attempt.get("content_type"),
        "body_complete": attempt.get("body_complete"),
        "parse_status": content.get("inspection_status") if isinstance(content, dict) else None,
        "parse_reason": content.get("reason") if isinstance(content, dict) else None,
        "document_sha256": content.get("document_sha256") if isinstance(content, dict) else None,
    }
    if (
        not attempt.get("endpoint_available")
        or attempt.get("stop_reason") != "terminal_response"
        or not isinstance(attempt.get("status_code"), int)
        or not 200 <= attempt["status_code"] <= 299
        or attempt.get("body_complete") is not True
        or not isinstance(content, dict)
        or content.get("inspection_status") != "COMPLETE"
    ):
        return None, detail
    return True, detail


def _aggregate(values: list[bool | None]) -> bool | None:
    if any(value is True for value in values):
        return True
    if values and all(value is False for value in values):
        return False
    return None


def _evaluation(matched: bool | None, reason: str, evidence: Any) -> dict[str, Any]:
    return {
        "matched": matched,
        "outcome": "MATCH" if matched is True else "NO_MATCH" if matched is False else "INDETERMINATE",
        "reason": reason,
        "policy_version": HTTP_CONTENT_POLICY_VERSION,
        "evidence": evidence,
    }


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
