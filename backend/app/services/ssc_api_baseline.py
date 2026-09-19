"""Explicit, read-only SSC metadata acquisition. Never used by the scan runtime."""
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Literal

import httpx
from pydantic import Field, ValidationError, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.catalog_models import BreachRiskEnum, CatalogSnapshot, SourceTypeEnum
from app.services.golden_baseline_importer import (
    BaselineFactorInput, BaselineIssueInput, GoldenBaselineInput,
)

API_ORIGIN = "https://api.securityscorecard.io"
FACTORS_ENDPOINT = "/metadata/factors"
ISSUES_ENDPOINT = "/metadata/issue-types"
API_SCHEMA_VERSION = "ssc.api.metadata.v2"
DETAIL_SAMPLE_KEYS = ("tls_weak_protocol", "cookie_missing_http_only", "csp_no_policy_v2")
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 20
DETAIL_MAX_WORKERS = 4
DETAIL_MAX_ATTEMPTS = 3
DETAIL_RETRY_MAX_DELAY_SECONDS = 60
TRANSIENT_HTTP_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
VERIFIED_DETAIL_FIELDS = frozenset({
    "key", "severity", "factor", "title", "short_description", "long_description", "recommendation",
})


class SSCAcquisitionError(ValueError):
    """Messages never include response bodies, headers, tokens or transport errors."""


class APIFactorInput(BaselineFactorInput):
    # All factors belong to the baseline, including those with no current issues.
    issues: list[BaselineIssueInput] = Field(default_factory=list)
    long_description: str | None = None
    ssc_metadata: dict


class APIBaselineInput(GoldenBaselineInput):
    schema_version: Literal["ssc.api.metadata.v2"] = API_SCHEMA_VERSION
    source_type: Literal["SSC_API"] = "SSC_API"
    factors: list[APIFactorInput] = Field(min_length=1)
    raw_source: dict
    detail_enrichment_requested: bool = False
    detail_enrichment_failures: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_baseline_consistency(self):
        # API keys establish identity; two authoritative keys may share a title.
        codes = [factor.code for factor in self.factors]
        keys = [issue.stable_key for factor in self.factors for issue in factor.issues]
        if len(codes) != len(set(codes)) or len(keys) != len(set(keys)) or not keys:
            raise ValueError("API baseline requires unique keys and nonempty issue membership")
        return self


def _parse_json(body: str):
    def reject_constant(_value):
        raise ValueError("Nonfinite JSON number")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key")
            result[key] = value
        return result

    return json.loads(body, parse_constant=reject_constant, object_pairs_hook=unique_object)


def _token_from_environment() -> str:
    token = os.environ.get("SSC_TOKEN", "").strip()
    if not token:
        raise SSCAcquisitionError("SSC_TOKEN must be set in the environment")
    if any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise SSCAcquisitionError("SSC_TOKEN contains invalid characters")
    return token


def _get(
    client: httpx.Client,
    endpoint: str,
    token: str,
    *,
    retry_transient: bool = False,
) -> dict:
    # Fixed origin and paths; no redirects or response-provided URLs are followed.
    attempts = DETAIL_MAX_ATTEMPTS if retry_transient else 1
    for attempt in range(attempts):
        try:
            with client.stream("GET", API_ORIGIN + endpoint,
                               headers={"Authorization": "Token " + token, "Accept": "application/json"}) as response:
                if response.status_code != 200:
                    if response.status_code in TRANSIENT_HTTP_STATUSES and attempt + 1 < attempts:
                        delay = _retry_delay(response, attempt)
                        if delay is not None:
                            time.sleep(delay)
                            continue
                    raise SSCAcquisitionError(f"SSC API {endpoint}: HTTP {response.status_code}")
                if "next" in response.links:
                    raise SSCAcquisitionError("Paginated SSC metadata requires review; no partial baseline imported")
                chunks = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise SSCAcquisitionError("SSC metadata exceeds the response size limit")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                body = raw.decode("utf-8")
                payload = _parse_json(body)
                # Fail closed if a server echoes credentials, including JSON-escaped text.
                if token in body or token in json.dumps(payload, ensure_ascii=False):
                    raise SSCAcquisitionError("SSC response contains credential material; response discarded")
                return {"body": body, "sha256": hashlib.sha256(raw).hexdigest(),
                        "captured_at": datetime.now(timezone.utc).isoformat()}
        except httpx.TransportError:
            if attempt + 1 < attempts:
                time.sleep(_retry_delay(None, attempt))
                continue
            raise SSCAcquisitionError(f"SSC API {endpoint}: request or JSON decoding failed") from None
        except (UnicodeError, ValueError) as exc:
            if isinstance(exc, SSCAcquisitionError):
                raise
            raise SSCAcquisitionError(f"SSC API {endpoint}: request or JSON decoding failed") from None
    raise SSCAcquisitionError(f"SSC API {endpoint}: request failed")


def _retry_delay(response: httpx.Response | None, attempt: int) -> float | None:
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                delay = float(retry_after)
            except ValueError:
                try:
                    delay = (parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds()
                except (TypeError, ValueError):
                    return None
            if delay <= DETAIL_RETRY_MAX_DELAY_SECONDS:
                return max(delay, 0)
            return None
    return min(0.25 * (2 ** attempt), DETAIL_RETRY_MAX_DELAY_SECONDS)


def acquire_baseline(
    *,
    enrich_details: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> APIBaselineInput:
    token = _token_from_environment()
    with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False,
                      trust_env=False, transport=transport) as client:
        raw_source = {API_ORIGIN + endpoint: _get(client, endpoint, token)
                      for endpoint in (FACTORS_ENDPOINT, ISSUES_ENDPOINT)}
        baseline = normalize_api_payloads(raw_source)
        if not enrich_details:
            return baseline

        issue_rows = {
            issue.stable_key: issue.ssc_metadata
            for factor in baseline.factors
            for issue in factor.issues
        }
        failures = {}
        with ThreadPoolExecutor(max_workers=DETAIL_MAX_WORKERS) as executor:
            futures = {
                executor.submit(_acquire_detail, client, token, key, row): key
                for key, row in issue_rows.items()
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    endpoint, capture = future.result()
                    raw_source[API_ORIGIN + endpoint] = capture
                except SSCAcquisitionError as exc:
                    failures[key] = str(exc)
    return normalize_api_payloads(
        raw_source,
        detail_enrichment_requested=True,
        detail_enrichment_failures=failures,
    )


def _acquire_detail(client: httpx.Client, token: str, key: str, list_row: dict) -> tuple[str, dict]:
    endpoint = ISSUES_ENDPOINT + "/" + key
    capture = _get(client, endpoint, token, retry_transient=True)
    payload = _parse_json(capture["body"])
    if not isinstance(payload, dict) or not VERIFIED_DETAIL_FIELDS.issubset(payload):
        raise SSCAcquisitionError(f"SSC API {endpoint}: invalid detail metadata")
    if any(payload[field] != list_row[field] for field in ("key", "severity", "factor", "title")):
        raise SSCAcquisitionError(f"SSC API {endpoint}: detail metadata does not match the issue list")
    if not all(isinstance(payload[field], str) for field in VERIFIED_DETAIL_FIELDS):
        raise SSCAcquisitionError(f"SSC API {endpoint}: invalid detail field type")
    return endpoint, capture


def normalize_api_payloads(
    raw_source: dict,
    *,
    detail_enrichment_requested: bool = False,
    detail_enrichment_failures: dict[str, str] | None = None,
) -> APIBaselineInput:
    """Validate complete responses; keep all original fields without interpreting severity."""
    try:
        records = {}
        for endpoint in (FACTORS_ENDPOINT, ISSUES_ENDPOINT):
            capture = raw_source[API_ORIGIN + endpoint]
            if hashlib.sha256(capture["body"].encode("utf-8")).hexdigest() != capture["sha256"]:
                raise ValueError("Raw source hash mismatch")
            payload = _parse_json(capture["body"])
            # Known contract is {entries: [...]}; unknown envelope fields are kept.
            if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list) or not payload["entries"]:
                raise ValueError("Expected nonempty entries")
            if any(payload.get(key) for key in ("next", "next_page", "next_url", "cursor", "pagination")):
                raise ValueError("Pagination is not a complete baseline")
            rows = payload["entries"]
            keys = [row["key"] for row in rows]
            if not all(isinstance(key, str) and key for key in keys) or len(set(keys)) != len(keys):
                raise ValueError("Invalid or duplicate keys")
            records[endpoint] = sorted(rows, key=lambda row: row["key"])
        detail_rows = {}
        detail_prefix = API_ORIGIN + ISSUES_ENDPOINT + "/"
        for url, capture in raw_source.items():
            if not url.startswith(detail_prefix):
                continue
            if hashlib.sha256(capture["body"].encode("utf-8")).hexdigest() != capture["sha256"]:
                raise ValueError("Raw detail source hash mismatch")
            detail = _parse_json(capture["body"])
            key = url.removeprefix(detail_prefix)
            if not isinstance(detail, dict) or detail.get("key") != key or not VERIFIED_DETAIL_FIELDS.issubset(detail):
                raise ValueError("Invalid issue detail metadata")
            detail_rows[key] = detail

        factors = []
        for row in records[FACTORS_ENDPOINT]:
            factors.append(APIFactorInput(code=row["key"], name=row["name"],
                                          description=row.get("description"), long_description=row.get("long_description"),
                                          ssc_metadata=row))
        factors_by_key = {factor.code: factor for factor in factors}
        for row in records[ISSUES_ENDPOINT]:
            factor = factors_by_key[row["factor"]]
            metadata = detail_rows.get(row["key"], row)
            if any(metadata[field] != row[field] for field in ("key", "severity", "factor", "title")):
                raise ValueError("Issue detail metadata does not match the issue list")
            factor.issues.append(BaselineIssueInput(
                stable_key=row["key"], name=row["title"], description=metadata.get("short_description"),
                ssc_severity=row["severity"], ssc_metadata=metadata,
                breach_risk=BreachRiskEnum.UNKNOWN, threat_level=None,
                # Existing conservative review gate: UNKNOWN prevents assessed scores.
                # This is internal policy, NOT a claim about SSC score impact.
                affects_score=True,
                source_reference=(detail_prefix + row["key"] if row["key"] in detail_rows
                                  else API_ORIGIN + ISSUES_ENDPOINT + "#" + row["key"]),
            ))
        captured_at = max(datetime.fromisoformat(capture["captured_at"]) for capture in raw_source.values())
        return APIBaselineInput(name="SSC API Golden Baseline", captured_at=captured_at,
                                source_reference=API_ORIGIN + FACTORS_ENDPOINT + " ; " + API_ORIGIN + ISSUES_ENDPOINT,
                                factors=factors, raw_source=raw_source,
                                detail_enrichment_requested=detail_enrichment_requested,
                                detail_enrichment_failures=detail_enrichment_failures or {})
    except (KeyError, TypeError, ValueError, ValidationError):
        raise SSCAcquisitionError("Invalid or incomplete SSC metadata; no baseline imported") from None


def discover_issue_details(*, transport: httpx.BaseTransport | None = None) -> dict:
    """Read only the three documented sample endpoints; report field paths, not values."""
    token = _token_from_environment()
    results = {}
    with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False,
                      trust_env=False, transport=transport) as client:
        for key in DETAIL_SAMPLE_KEYS:
            endpoint = ISSUES_ENDPOINT + "/" + key
            try:
                capture = _get(client, endpoint, token)
                payload = _parse_json(capture["body"])
                if not isinstance(payload, dict):
                    raise SSCAcquisitionError("Expected a metadata object")
                results[key] = {"endpoint": API_ORIGIN + endpoint, "status": 200,
                                "fields": sorted(payload), "field_paths": _field_paths(payload),
                                "captured_at": capture["captured_at"], "sha256": capture["sha256"]}
            except SSCAcquisitionError as exc:
                results[key] = {"endpoint": API_ORIGIN + endpoint, "error": str(exc)}
    return results


def _field_paths(value, prefix="") -> list[str]:
    paths = set()
    if isinstance(value, dict):
        for key, item in value.items():
            path = prefix + "." + key if prefix else key
            paths.add(path)
            paths.update(_field_paths(item, path))
    elif isinstance(value, list):
        for item in value:
            paths.update(_field_paths(item, prefix + "[]"))
    return sorted(paths)


def taxonomy_status(db: Session) -> str:
    real_baseline = db.scalar(select(CatalogSnapshot.id).where(
        CatalogSnapshot.is_real_baseline.is_(True),
        CatalogSnapshot.source_type.in_([SourceTypeEnum.SSC_API, SourceTypeEnum.SSC_LICENSED_UI]),
    ).limit(1))
    return "SSC_ALIGNED" if real_baseline else "INTERNAL_ONLY"
