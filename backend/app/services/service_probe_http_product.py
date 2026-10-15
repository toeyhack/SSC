"""Pure, bounded Wave 5D HTTP exact-product identity evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any


HTTP_PRODUCT_FRAMEWORK_VERSION = "http-product-probe-framework.v1"
HTTP_PRODUCT_POLICY_VERSION = "ssc-wave5d-http-product-identification.v1"
COUCHDB_IDENTITY_POLICY_VERSION = "ssc-wave5d-couchdb-identity.v1"
ELASTICSEARCH_IDENTITY_POLICY_VERSION = "ssc-wave5d-elasticsearch-identity.v1"
HTTP_PRODUCT_EVIDENCE_SCHEMA_VERSION = "ssc-wave5d-http-product-evidence.v1"

MAX_HTTP_PRODUCT_ENDPOINTS = 4
MAX_HTTP_PRODUCT_RESPONSE_BYTES = 16_384
MAX_HTTP_PRODUCT_HEADERS = 64
MAX_HTTP_PRODUCT_HEADER_BYTES = 32_768
MAX_HTTP_PRODUCT_HEADER_VALUE_BYTES = 8_192
DEFAULT_HTTP_PRODUCT_DEADLINE_SECONDS = 5.0
MAX_HTTP_PRODUCT_DEADLINE_SECONDS = 10.0
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 128
MAX_JSON_OBJECT_MEMBERS = 64
MAX_JSON_ARRAY_ELEMENTS = 32
MAX_JSON_KEY_BYTES = 64
MAX_JSON_STRING_BYTES = 256
MAX_JSON_NUMBER_BYTES = 32

PRODUCT_ISSUE_KEYS = {
    "couchdb": "service_couchdb",
    "elasticsearch": "service_elasticsearch",
}
_VERSION = re.compile(r"^[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}(?:[-+][0-9A-Za-z.-]{1,64})?$")
_OPENSEARCH_TAGLINE = "The OpenSearch Project: https://opensearch.org/"


class _JSONLimitError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _JSONLimitError("duplicate_json_key")
        result[key] = value
    return result


def _number(value: str) -> int | float:
    if len(value.encode("ascii")) > MAX_JSON_NUMBER_BYTES:
        raise _JSONLimitError("numeric_literal_too_long")
    return float(value) if any(ch in value for ch in ".eE") else int(value)


def _reject_constant(_: str) -> Any:
    raise _JSONLimitError("non_finite_number")


def _strict_document(body: bytes) -> tuple[Any | None, dict[str, int], str | None]:
    counts = {"depth": 0, "nodes": 0, "max_object_members": 0, "max_array_elements": 0}
    try:
        text = body.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_number,
            parse_float=_number,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError:
        return None, counts, "invalid_utf8"
    except _JSONLimitError as exc:
        return None, counts, str(exc)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return None, counts, "malformed_json"

    def visit(value: Any, depth: int) -> None:
        counts["depth"] = max(counts["depth"], depth)
        counts["nodes"] += 1
        if depth > MAX_JSON_DEPTH or counts["nodes"] > MAX_JSON_NODES:
            raise _JSONLimitError("json_structural_limit")
        if isinstance(value, dict):
            counts["max_object_members"] = max(counts["max_object_members"], len(value))
            if len(value) > MAX_JSON_OBJECT_MEMBERS:
                raise _JSONLimitError("json_structural_limit")
            for key, child in value.items():
                try:
                    key_bytes = len(key.encode("utf-8", errors="strict"))
                except UnicodeEncodeError as exc:
                    raise _JSONLimitError("invalid_unicode_scalar") from exc
                if key_bytes > MAX_JSON_KEY_BYTES:
                    raise _JSONLimitError("json_key_too_long")
                visit(child, depth + 1)
        elif isinstance(value, list):
            counts["max_array_elements"] = max(counts["max_array_elements"], len(value))
            if len(value) > MAX_JSON_ARRAY_ELEMENTS:
                raise _JSONLimitError("json_structural_limit")
            for child in value:
                visit(child, depth + 1)
        elif isinstance(value, str):
            try:
                string_bytes = len(value.encode("utf-8", errors="strict"))
            except UnicodeEncodeError as exc:
                raise _JSONLimitError("invalid_unicode_scalar") from exc
            if string_bytes > MAX_JSON_STRING_BYTES:
                raise _JSONLimitError("json_string_too_long")

    try:
        visit(document, 1)
    except _JSONLimitError as exc:
        return None, counts, str(exc)
    return document, counts, None


def _media_type(value: Any) -> str:
    return value.split(";", 1)[0].strip().casefold() if isinstance(value, str) else ""


def _valid_version(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= MAX_JSON_STRING_BYTES and bool(_VERSION.fullmatch(value))
    except UnicodeEncodeError:
        return False


def _nonempty(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= MAX_JSON_STRING_BYTES
    except UnicodeEncodeError:
        return False


def _header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value.strip() for key, value in headers if key.casefold() == name.casefold()]


def _header_limits(headers: list[tuple[str, str]]) -> str | None:
    if len(headers) > MAX_HTTP_PRODUCT_HEADERS:
        return "header_count_limit"
    total = 0
    for name, value in headers:
        name_bytes = len(name.encode("utf-8", errors="replace"))
        value_bytes = len(value.encode("utf-8", errors="replace"))
        if name_bytes > MAX_HTTP_PRODUCT_HEADER_VALUE_BYTES or value_bytes > MAX_HTTP_PRODUCT_HEADER_VALUE_BYTES:
            return "individual_header_limit"
        total += name_bytes + value_bytes + 4
    return "header_bytes_limit" if total > MAX_HTTP_PRODUCT_HEADER_BYTES else None


def _couchdb_facts(document: Any, server_values: list[str]) -> tuple[bool, dict[str, bool]]:
    root = document if isinstance(document, dict) else {}
    vendor = root.get("vendor")
    facts = {
        "couchdb_welcome_exact": root.get("couchdb") == "Welcome",
        "apache_vendor_exact": isinstance(vendor, dict) and vendor.get("name") == "The Apache Software Foundation",
        "version_format_valid": _valid_version(root.get("version")),
        "server_header_couchdb": any(value.casefold().startswith("couchdb") for value in server_values),
    }
    return all(facts[key] for key in ("couchdb_welcome_exact", "apache_vendor_exact", "version_format_valid")), facts


def _elasticsearch_facts(document: Any, product_values: list[str]) -> tuple[bool, dict[str, bool]]:
    root = document if isinstance(document, dict) else {}
    version = root.get("version") if isinstance(root.get("version"), dict) else {}
    typed = (
        _valid_version(version.get("number"))
        and all(_nonempty(version.get(key)) for key in ("build_flavor", "build_type", "build_hash", "build_date"))
        and all(_valid_version(version.get(key)) for key in (
            "lucene_version", "minimum_wire_compatibility_version", "minimum_index_compatibility_version",
        ))
        and isinstance(version.get("build_snapshot"), bool)
    )
    facts = {
        "elastic_product_header_single": len(product_values) == 1,
        "elastic_product_header_exact": len(product_values) == 1 and product_values[0] == "Elasticsearch",
        "root_identity_strings_valid": all(_nonempty(root.get(key)) for key in ("name", "cluster_name", "cluster_uuid")),
        "version_object_present": isinstance(root.get("version"), dict),
        "version_format_valid": _valid_version(version.get("number")),
        "typed_build_structure_valid": typed,
        "elastic_tagline_exact": root.get("tagline") == "You Know, for Search",
        "opensearch_distribution": version.get("distribution") == "opensearch",
        "opensearch_tagline_exact": root.get("tagline") == _OPENSEARCH_TAGLINE,
    }
    match = (
        facts["elastic_product_header_exact"]
        and facts["root_identity_strings_valid"]
        and facts["typed_build_structure_valid"]
        and facts["elastic_tagline_exact"]
        and not facts["opensearch_distribution"]
        and not facts["opensearch_tagline_exact"]
    )
    return match, facts


def evaluate_http_product_response(
    product: str,
    observation: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate one acquired response and return privacy-minimized evidence."""
    if product not in PRODUCT_ISSUE_KEYS:
        raise ValueError("unsupported HTTP product")
    body = observation.get("_body") if isinstance(observation.get("_body"), bytes) else b""
    headers = observation.get("_header_pairs")
    headers = headers if isinstance(headers, list) and all(isinstance(v, tuple) and len(v) == 2 for v in headers) else []
    header_error = _header_limits(headers)
    content_types = _header_values(headers, "content-type")
    encodings = _header_values(headers, "content-encoding")
    product_headers = _header_values(headers, "x-elastic-product")
    server_headers = _header_values(headers, "server")
    media_type = _media_type(content_types[0]) if len(content_types) == 1 else ""
    document, structural_counts, json_error = _strict_document(body) if body else (None, {"depth": 0, "nodes": 0, "max_object_members": 0, "max_array_elements": 0}, "empty_body")
    couch_signature, couch_facts = _couchdb_facts(document, server_headers)
    elastic_signature, elastic_facts = _elasticsearch_facts(document, product_headers)
    couch_content_ok = media_type in {"application/json", "text/plain"}
    elastic_content_ok = media_type in {"application/json", "application/vnd.elasticsearch+json"}
    couch_exact = couch_signature and couch_content_ok
    elastic_exact = elastic_signature and elastic_content_ok
    opensearch_exact = elastic_content_ok and (
        isinstance(document, dict)
        and elastic_facts["opensearch_distribution"]
        and elastic_facts["opensearch_tagline_exact"]
        and not elastic_facts["elastic_product_header_exact"]
    )
    marker_facts = couch_facts if product == "couchdb" else elastic_facts
    status = observation.get("status_code")
    body_complete = observation.get("body_complete") is True
    requested_content_ok = couch_content_ok if product == "couchdb" else elastic_content_ok
    reviewed_content_ok = requested_content_ok or couch_exact or elastic_exact or opensearch_exact
    common_error = (
        _compact_error_class(observation)
        or ("non_terminal_response" if observation.get("stop_reason") != "terminal_response" else None)
        or ("status_not_200" if status != 200 else None)
        or ("incomplete_body" if not body_complete else None)
        or ("response_body_limit" if len(body) > MAX_HTTP_PRODUCT_RESPONSE_BYTES else None)
        or ("unsupported_content_encoding" if any(value.casefold() not in {"", "identity"} for value in encodings) else None)
        or header_error
        or ("content_type_not_accepted" if not reviewed_content_ok else None)
        or json_error
        or ("json_root_not_object" if document is not None and not isinstance(document, dict) else None)
    )
    conflicting = (couch_exact and (elastic_exact or opensearch_exact)) or (elastic_exact and opensearch_exact)
    if common_error or conflicting:
        outcome, identity_class = "INDETERMINATE", "CONFLICTING" if conflicting else "UNKNOWN"
        reason = "conflicting_product_markers" if conflicting else str(common_error)
    elif product == "couchdb" and couch_exact:
        outcome, identity_class, reason = "MATCH", "APACHE_COUCHDB", "exact_apache_couchdb_signature"
    elif product == "elasticsearch" and elastic_exact:
        outcome, identity_class, reason = "MATCH", "ELASTICSEARCH", "exact_elasticsearch_signature"
    elif product == "elasticsearch" and opensearch_exact:
        outcome, identity_class, reason = "NO_MATCH", "OPENSEARCH", "exact_opensearch_signature"
    elif product == "couchdb" and elastic_exact:
        outcome, identity_class, reason = "NO_MATCH", "ELASTICSEARCH", "exact_elasticsearch_signature"
    elif product == "couchdb" and opensearch_exact:
        outcome, identity_class, reason = "NO_MATCH", "OPENSEARCH", "exact_opensearch_signature"
    elif product == "elasticsearch" and couch_exact:
        outcome, identity_class, reason = "NO_MATCH", "APACHE_COUCHDB", "exact_apache_couchdb_signature"
    else:
        outcome, identity_class, reason = "INDETERMINATE", "UNKNOWN", "identity_signature_incomplete"

    observed_at = observation.get("observed_at")
    if not isinstance(observed_at, str):
        observed_at = datetime.now(timezone.utc).isoformat()
    policy = COUCHDB_IDENTITY_POLICY_VERSION if product == "couchdb" else ELASTICSEARCH_IDENTITY_POLICY_VERSION
    return {
        "product": product,
        "issue_key": PRODUCT_ISSUE_KEYS[product],
        "transport": observation.get("request_scheme"),
        "port": observation.get("request_port"),
        "request_method": "GET",
        "request_path": "/",
        "terminal_transport": observation.get("terminal_scheme"),
        "terminal_port": observation.get("terminal_port"),
        "redirect_count": max(0, len(observation.get("redirect_chain", [])) - 1),
        "status_code": status,
        "required_header_present": bool(product_headers) if product == "elasticsearch" else None,
        "required_header_exact": (len(product_headers) == 1 and product_headers[0] == "Elasticsearch") if product == "elasticsearch" else None,
        "content_type_class": media_type or "UNKNOWN",
        "response_sha256": hashlib.sha256(body).hexdigest() if body else None,
        "response_bytes": len(body),
        "body_complete": body_complete,
        "structural_counts": {**structural_counts, "header_count": len(headers), "header_bytes": sum(len(n.encode("utf-8", errors="replace")) + len(v.encode("utf-8", errors="replace")) + 4 for n, v in headers)},
        "marker_facts": marker_facts,
        "identity_class": identity_class,
        "outcome": outcome,
        "matched": True if outcome == "MATCH" else False if outcome == "NO_MATCH" else None,
        "reason_code": reason,
        "framework_version": HTTP_PRODUCT_FRAMEWORK_VERSION,
        "identity_policy_version": policy,
        "evidence_schema_version": HTTP_PRODUCT_EVIDENCE_SCHEMA_VERSION,
        "completion_reason": observation.get("completion_reason", "complete" if body_complete else "incomplete"),
        "stop_reason": observation.get("stop_reason"),
        "error_class": _compact_error_class(observation),
        "certificate_trust": observation.get("certificate_trusted"),
        "elapsed_ms": observation.get("elapsed_ms"),
        "observed_at": observed_at,
    }


def _compact_error_class(observation: dict[str, Any]) -> str | None:
    """Keep only a bounded machine class; never retain transport/server prose."""
    error = observation.get("error")
    if error is None:
        return None
    stop_reason = observation.get("stop_reason")
    if isinstance(stop_reason, str) and stop_reason:
        return stop_reason[:64]
    if isinstance(error, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,63}", error):
        return error
    return "transport_error"


def aggregate_http_product_evaluations(product: str, observations: list[dict[str, Any]]) -> dict[str, Any]:
    if any(item.get("outcome") == "MATCH" for item in observations):
        outcome, reason = "MATCH", "one_declared_endpoint_matched"
    elif observations and all(item.get("outcome") == "NO_MATCH" for item in observations):
        outcome, reason = "NO_MATCH", "all_declared_endpoints_are_reviewed_different_products"
    else:
        outcome, reason = "INDETERMINATE", "one_or_more_declared_endpoints_indeterminate"
    return {
        "matched": True if outcome == "MATCH" else False if outcome == "NO_MATCH" else None,
        "outcome": outcome,
        "reason": reason,
        "policy_version": HTTP_PRODUCT_POLICY_VERSION,
        "evidence": observations,
    }
