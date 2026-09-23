import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
import math
import re
import secrets
import warnings

import dns.resolver
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.models import Domain, Host, Organization
from app.models.scan_models import EvidenceSourceEnum, ScanJobTarget, ScanTargetTypeEnum
from app.services.service_probes import (
    ADAPTERS as SERVICE_PROBE_ADAPTERS,
    MAX_SERVICE_PROBES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
    SERVICE_PROBE_FRAMEWORK_VERSION,
    aggregate_service_probe_evaluations,
    evaluate_service_probe_response,
    run_service_probe,
)


USER_AGENT = "InternalSecurityRatingScanner/Phase4B"
METADATA_IPS = {"169.254.169.254", "100.100.100.200"}
MAX_HTTP_PORTS = 4
MAX_TCP_PORTS = 10
MAX_TLS_PORTS = 3
MAX_HTTP_PATHS = 20
WAVE1_POLICY_VERSION = "ssc-wave1-security-policy.v1"
WAVE2_TLS_POLICY_VERSION = "ssc-wave2-tls-policy.v1"
WAVE2_EMAIL_POLICY_VERSION = "ssc-wave2-email-policy.v1"


class ScanExecutorError(ValueError):
    pass


@dataclass(frozen=True)
class InventoryScanTarget:
    target_type: ScanTargetTypeEnum
    inventory_id: str
    hostname: str
    connect_host: str
    domain_name: str
    allow_sensitive_network_scan: bool


@dataclass(frozen=True)
class ExecutorObservation:
    evidence_source: EvidenceSourceEnum
    evidence: dict[str, Any]


class BaseExecutor:
    evidence_source: EvidenceSourceEnum
    executor_name: str

    def collect(self, target: InventoryScanTarget, config: dict[str, Any]) -> ExecutorObservation:
        raise NotImplementedError


class HTTPExecutor(BaseExecutor):
    evidence_source = EvidenceSourceEnum.SCANNER_HTTP
    executor_name = "http"

    def collect(self, target: InventoryScanTarget, config: dict[str, Any]) -> ExecutorObservation:
        target = _pin_target(target)
        timeout = _float_config(config, "request_timeout_seconds", 5.0, minimum=0.1, maximum=30.0)
        redirect_limit = _int_config(config, "redirect_limit", 5, minimum=0, maximum=10)
        response_size_limit = _int_config(config, "response_size_limit_bytes", 65536, minimum=1024, maximum=262144)
        http_ports = _ports_config(config, "http_ports", [80], MAX_HTTP_PORTS)
        https_ports = _ports_config(config, "https_ports", [443], MAX_HTTP_PORTS)
        paths = _http_paths_config(config)
        declared_scope = "http_paths" in config

        attempts: list[dict[str, Any]] = []
        selected: dict[str, Any] | None = None
        for scheme, ports in (("http", http_ports), ("https", https_ports)):
            for port in ports:
                for path in paths:
                    result = self._request_chain(
                        target, scheme, port, path, timeout, redirect_limit,
                        response_size_limit, set(http_ports), set(https_ports),
                    )
                    result["coverage_declared"] = declared_scope
                    attempts.append(_compact_attempt(result))
                    if result.get("endpoint_available") and (selected is None or (scheme == "https" and not result.get("error"))):
                        selected = result

        if selected is None and attempts:
            selected = attempts[0]
        selected = selected or {}
        headers = selected.get("headers") if isinstance(selected.get("headers"), dict) else {}
        cookies = selected.get("cookies") if isinstance(selected.get("cookies"), list) else []
        redirect_chain = selected.get("redirect_chain") if isinstance(selected.get("redirect_chain"), list) else []

        evaluations = _evaluate_http_wave1(attempts)
        evidence = {
            "executor": self.executor_name,
            "status": "success",
            "target_hostname": target.hostname,
            "target_identity": {
                "target_type": target.target_type.value,
                "inventory_id": target.inventory_id,
                "connect_host": target.connect_host,
            },
            "endpoint_available": bool(selected.get("endpoint_available", False)),
            "status_code": selected.get("status_code"),
            "headers": headers,
            "declared_paths": paths,
            "coverage_manifest": [
                {
                    "scheme": attempt.get("request_scheme"),
                    "port": attempt.get("request_port"),
                    "path": attempt.get("request_path"),
                    "endpoint_available": attempt.get("endpoint_available"),
                    "stop_reason": attempt.get("stop_reason"),
                }
                for attempt in attempts
            ],
            "redirect_chain": redirect_chain,
            "http_to_https_redirect": any(_http_to_https_redirect(attempt["redirect_chain"]) for attempt in attempts),
            # Preserved Phase 4B summary: any redirected HTTP hop. Exact SSC
            # semantics live under evaluations.redirect_chain_contains_http_v2.
            "redirect_chain_contains_insecure_http": any(_redirect_chain_mentions_http(attempt["redirect_chain"]) for attempt in attempts),
            "hsts_present": bool(_header_values(headers, "strict-transport-security")) if redirect_chain and redirect_chain[-1].get("scheme") == "https" else None,
            "csp_present": bool(_header_values(headers, "content-security-policy")),
            "x_content_type_options_present": bool(_header_values(headers, "x-content-type-options")),
            "clickjacking_protection_present": (
                bool(_header_values(headers, "x-frame-options"))
                or any("frame-ancestors" in value.lower() for value in _header_values(headers, "content-security-policy"))
            ),
            "cookies": cookies,
            "all_cookies_secure": _all_cookie_attr(cookies, "secure"),
            "all_cookies_httponly": _all_cookie_attr(cookies, "httponly"),
            "attempts": attempts,
            "evaluations": evaluations,
            "policy_version": WAVE1_POLICY_VERSION,
        }
        if selected.get("error") or not any(attempt.get("endpoint_available") for attempt in attempts):
            evidence["error"] = selected.get("error", "http_connection_failed")
            evidence["status"] = "error"
        return ExecutorObservation(self.evidence_source, evidence)

    def _request_chain(
        self,
        target: InventoryScanTarget,
        scheme: str,
        port: int,
        initial_path: str,
        timeout: float,
        redirect_limit: int,
        response_size_limit: int,
        http_ports: set[int],
        https_ports: set[int],
    ) -> dict[str, Any]:
        url_hostname = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
        url = f"{scheme}://{url_hostname}:{port}{initial_path}"
        redirect_chain: list[dict[str, Any]] = []
        current_url = url
        last_result: dict[str, Any] = {
            "endpoint_available": False,
            "status_code": None,
            "headers": {},
            "cookies": [],
            "redirect_chain": redirect_chain,
            "request_scheme": scheme,
            "request_port": port,
            "request_path": initial_path,
            "start_url": url,
            "stop_reason": "not_started",
        }

        for _ in range(redirect_limit + 1):
            parsed = urlparse(current_url)
            if parsed.scheme not in {"http", "https"}:
                last_result["error"] = f"unsupported redirect scheme: {parsed.scheme}"
                last_result["stop_reason"] = "unsupported_scheme"
                return last_result
            if not _same_target_host(parsed.hostname, target):
                last_result["error"] = "redirect target is outside approved inventory target"
                last_result["stop_reason"] = "outside_approved_target"
                return last_result

            try:
                port_number = parsed.port or (443 if parsed.scheme == "https" else 80)
            except ValueError:
                last_result["error"] = "invalid redirect port"
                last_result["stop_reason"] = "invalid_redirect_port"
                return last_result
            if port_number not in (https_ports if parsed.scheme == "https" else http_ports):
                last_result["error"] = "redirect port is outside configured scan ports"
                last_result["stop_reason"] = "outside_configured_ports"
                return last_result
            if parsed.username is not None or parsed.password is not None:
                last_result["error"] = "redirect credentials are not allowed"
                last_result["stop_reason"] = "redirect_credentials_rejected"
                return last_result
            try:
                result = self._single_request(
                    target=target,
                    scheme=parsed.scheme,
                    port=port_number,
                    path=parsed.path or "/",
                    query=parsed.query,
                    timeout=timeout,
                    response_size_limit=response_size_limit,
                )
            except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
                last_result["error"] = exc.__class__.__name__
                last_result["stop_reason"] = "request_error"
                return last_result

            if parsed.scheme == "https":
                result["certificate_trusted"] = _certificate_trust(
                    target.connect_host, target.hostname, port_number, timeout
                )

            location = result.get("location")
            location_scheme = None
            if location:
                location_scheme = urlparse(urljoin(current_url, str(location))).scheme
            redirect_chain.append(
                {
                    "scheme": parsed.scheme,
                    "host": parsed.hostname,
                    "port": port_number,
                    "status_code": result["status_code"],
                    "location_scheme": location_scheme,
                    "location_host": urlparse(urljoin(current_url, str(location))).hostname if location else None,
                    "path": parsed.path or "/",
                    "certificate_trusted": result.get("certificate_trusted") if parsed.scheme == "https" else None,
                }
            )
            last_result = {
                **result,
                "redirect_chain": redirect_chain,
                "request_scheme": scheme,
                "request_port": port,
                "request_path": initial_path,
                "start_url": url,
                "terminal_scheme": parsed.scheme,
            }

            if result["status_code"] not in {301, 302, 303, 307, 308} or not location:
                last_result["stop_reason"] = "terminal_response"
                return last_result
            current_url = urljoin(current_url, str(location))

        last_result["error"] = "redirect limit exceeded"
        last_result["stop_reason"] = "redirect_limit_exceeded"
        return last_result

    def _single_request(
        self,
        target: InventoryScanTarget,
        scheme: str,
        port: int,
        path: str,
        query: str,
        timeout: float,
        response_size_limit: int,
    ) -> dict[str, Any]:
        path_and_query = f"{path}?{query}" if query else path
        connection = http.client.HTTPConnection(target.hostname, port, timeout=timeout)
        raw_socket = socket.create_connection((target.connect_host, port), timeout=timeout)
        if scheme == "https":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Observation only; TLSExecutor separately checks trust.
            try:
                connection.sock = context.wrap_socket(raw_socket, server_hostname=target.hostname)
            except Exception:
                raw_socket.close()
                raise
        else:
            connection.sock = raw_socket
        try:
            connection.request(
                "GET",
                path_and_query,
                headers={
                    "Host": (f"[{target.hostname}]" if ":" in target.hostname else target.hostname) + (f":{port}" if port not in {80, 443} else ""),
                    "User-Agent": USER_AGENT,
                    "Accept": "*/*",
                    "Range": f"bytes=0-{max(response_size_limit - 1, 0)}",
                },
            )
            response = connection.getresponse()
            body = response.read(response_size_limit)
            normalized_headers, cookies = _normalize_http_headers(response)
            content_type = _first_header(normalized_headers, "content-type")
            meta_policies = _extract_csp_meta(body, content_type)
            return {
                "endpoint_available": True,
                "status_code": response.status,
                "headers": normalized_headers,
                "cookies": cookies,
                "content_type": content_type,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes_captured": len(body),
                "csp_meta_policies": meta_policies,
                "location": response.getheader("Location"),
            }
        finally:
            connection.close()


class TLSExecutor(BaseExecutor):
    evidence_source = EvidenceSourceEnum.SCANNER_TLS
    executor_name = "tls"

    def collect(self, target: InventoryScanTarget, config: dict[str, Any]) -> ExecutorObservation:
        target = _pin_target(target)
        timeout = _float_config(config, "connect_timeout_seconds", 5.0, minimum=0.1, maximum=30.0)
        ports = _ports_config(config, "tls_ports", [_int_config(config, "tls_port", 443, minimum=1, maximum=65535)], MAX_TLS_PORTS)
        trusted_self_signed = _fingerprint_allowlist(config)
        results = []
        for port in ports:
            metadata = _certificate_metadata(
                target.connect_host,
                target.hostname,
                port,
                timeout,
                trusted_self_signed=trusted_self_signed,
            )
            handshake = _collect_tls_handshake_evidence(
                target.connect_host, target.hostname, port, timeout,
            )
            result = {
                "port": port,
                **metadata,
                "handshake_observation": handshake,
                # Backwards-compatible summaries; exact Wave 2 evidence is above.
                "tls10_supported": handshake["protocols"]["TLSv1.0"].get("accepted"),
                "tls11_supported": handshake["protocols"]["TLSv1.1"].get("accepted"),
            }
            result["evaluations"] = {
                **metadata.get("evaluations", {}),
                **_evaluate_tls_handshake(handshake),
            }
            results.append(result)
        selected = next((result for result in results if result.get("endpoint_available")), results[0])
        evidence = {
            "executor": self.executor_name,
            "status": "success" if all(result.get("endpoint_available") for result in results) else "error",
            "target_hostname": target.hostname,
            "target_identity": {"target_type": target.target_type.value, "inventory_id": target.inventory_id, "connect_host": target.connect_host},
            **selected,
            "ports": {str(result["port"]): result for result in results},
            "evaluations": _aggregate_evaluations(results),
            "policy_version": WAVE1_POLICY_VERSION,
            "handshake_policy_version": WAVE2_TLS_POLICY_VERSION,
        }
        if not selected.get("endpoint_available"):
            evidence["error"] = selected.get("certificate_error", "tls_connection_failed")
        return ExecutorObservation(self.evidence_source, evidence)


class DNSExecutor(BaseExecutor):
    evidence_source = EvidenceSourceEnum.SCANNER_DNS
    executor_name = "dns"

    def collect(self, target: InventoryScanTarget, config: dict[str, Any]) -> ExecutorObservation:
        timeout = _float_config(config, "dns_timeout_seconds", 3.0, minimum=0.1, maximum=15.0)
        server_host = config.get("dns_server_host")
        if server_host:
            resolver_target = replace(target, connect_host=str(server_host))
            server_host = _pin_target(resolver_target).connect_host
        server_port = _int_config(config, "dns_server_port", 53, minimum=1, maximum=65535)
        domain = target.domain_name

        root_txt = _query_txt_evidence(domain, server_host, server_port, timeout)
        dmarc_txt = _query_txt_evidence(f"_dmarc.{domain}", server_host, server_port, timeout)
        nonce_queries = [
            _query_txt_evidence(f"_ssc-spf-{secrets.token_hex(8)}.{domain}", server_host, server_port, timeout)
            for _ in range(2)
        ]
        subdomains = _email_subdomains_config(config, domain)
        subdomain_dmarc = [
            {
                "subdomain": subdomain,
                "query": _query_txt_evidence(f"_dmarc.{subdomain}", server_host, server_port, timeout),
            }
            for subdomain in subdomains
        ]
        spf_analysis = _analyze_spf(domain, root_txt, server_host, server_port, timeout)
        dmarc_analysis = _analyze_dmarc(dmarc_txt)
        evaluations = _evaluate_email_security(
            domain, root_txt, spf_analysis, dmarc_txt, dmarc_analysis,
            nonce_queries, subdomain_dmarc,
        )
        spf_records = root_txt["records"]
        dmarc_records = dmarc_txt["records"]
        error = root_txt.get("error") or dmarc_txt.get("error")
        evidence = {
            "executor": self.executor_name,
            "status": "success",
            "target_domain": domain,
            "target_identity": {
                "target_type": target.target_type.value,
                "inventory_id": target.inventory_id,
            },
            "spf_present": None if error else any(record.lower().startswith("v=spf1") for record in spf_records),
            "spf_records": spf_records,
            "dmarc_present": None if error else any(record.lower().startswith("v=dmarc1") for record in dmarc_records),
            "dmarc_records": dmarc_records,
            "queries": {
                "domain_txt": root_txt,
                "dmarc_txt": dmarc_txt,
                "spf_wildcard_nonce_txt": nonce_queries,
                "subdomain_dmarc_txt": subdomain_dmarc,
            },
            "spf_analysis": spf_analysis,
            "dmarc_analysis": dmarc_analysis,
            "declared_subdomains": subdomains,
            "evaluations": evaluations,
            "policy_version": WAVE2_EMAIL_POLICY_VERSION,
        }
        if error:
            evidence["error"] = error
            evidence["status"] = "error"
        return ExecutorObservation(self.evidence_source, evidence)


class TCPExecutor(BaseExecutor):
    evidence_source = EvidenceSourceEnum.SCANNER_TCP
    executor_name = "tcp"

    def collect(self, target: InventoryScanTarget, config: dict[str, Any]) -> ExecutorObservation:
        target = _pin_target(target)
        timeout = _float_config(config, "connect_timeout_seconds", 3.0, minimum=0.1, maximum=15.0)
        ports = _ports_config(config, "tcp_ports", [], MAX_TCP_PORTS)
        probe_timeout = _float_config(config, "service_probe_timeout_seconds", timeout, minimum=0.1, maximum=15.0)
        response_limit = _int_config(
            config, "service_probe_response_limit_bytes", 4096,
            minimum=64, maximum=MAX_SERVICE_PROBE_RESPONSE_BYTES,
        )
        configured_probes = _service_probes_config(config)
        evidence = {
            "executor": self.executor_name,
            "status": "success",
            "target_hostname": target.hostname,
            "target_identity": {
                "target_type": target.target_type.value,
                "inventory_id": target.inventory_id,
                "connect_host": target.connect_host,
            },
            "ports": {},
            "service_probes": [],
            "probe_framework_version": SERVICE_PROBE_FRAMEWORK_VERSION,
        }
        for port in ports:
            started = time.monotonic()
            is_open = False
            error = None
            try:
                with socket.create_connection((target.connect_host, port), timeout=timeout):
                    is_open = True
            except (OSError, TimeoutError) as exc:
                error = exc.__class__.__name__
            evidence["ports"][str(port)] = {
                "open": is_open,
                "error": error,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        for configured in configured_probes:
            protocol = configured["protocol"]
            port = configured["port"]
            transport = configured["transport"]
            if transport == "tcp":
                attempt = run_service_probe(
                    target.connect_host, port, protocol,
                    timeout=probe_timeout, response_limit=response_limit,
                )
            else:
                observed_at = datetime.now(timezone.utc).isoformat()
                adapter = SERVICE_PROBE_ADAPTERS[protocol]
                attempt = {
                    "protocol": protocol,
                    "issue_key": adapter.issue_key,
                    "transport": transport,
                    "port": port,
                    "probe_type": adapter.probe_type,
                    "probe_version": adapter.probe_version,
                    "framework_version": SERVICE_PROBE_FRAMEWORK_VERSION,
                    "started_at": observed_at,
                    "completed_at": observed_at,
                    "elapsed_ms": 0,
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "response_sha256": None,
                    "stop_reason": "unsupported_transport",
                    "error_class": None,
                    **evaluate_service_probe_response(protocol, b"", transport=transport),
                }
            evidence["service_probes"].append(attempt)
        evidence["evaluations"] = aggregate_service_probe_evaluations(evidence["service_probes"])
        if not ports and not configured_probes:
            evidence["skipped"] = "no tcp_ports or service_probes configured"
            evidence["status"] = "skipped"
        return ExecutorObservation(self.evidence_source, evidence)


EXECUTOR_BY_NAME: dict[str, BaseExecutor] = {
    "http": HTTPExecutor(),
    "tls": TLSExecutor(),
    "dns": DNSExecutor(),
    "tcp": TCPExecutor(),
}


def collect_scanner_observations(target: InventoryScanTarget, config: dict[str, Any] | None) -> list[ExecutorObservation]:
    normalized_config = validate_scan_config(config)
    executor_names = normalized_config.get("executors")
    if executor_names is None:
        executor_names = ["http", "tls", "dns"]
        if normalized_config.get("tcp_ports") or normalized_config.get("service_probes"):
            executor_names.append("tcp")
    if not isinstance(executor_names, list) or not all(isinstance(name, str) for name in executor_names):
        raise ScanExecutorError("scan_config.executors must be a list of executor names")

    executor_names = list(dict.fromkeys(name.lower() for name in executor_names))
    observations: list[ExecutorObservation] = []
    min_interval = _float_config(normalized_config, "per_target_interval_seconds", 0.05, minimum=0.0, maximum=2.0)
    last_started = 0.0
    for name in executor_names:
        executor = EXECUTOR_BY_NAME.get(name.lower())
        if executor is None:
            raise ScanExecutorError(f"Unsupported scanner executor: {name}")
        now = time.monotonic()
        wait = min_interval - (now - last_started)
        if wait > 0:
            time.sleep(wait)
        last_started = time.monotonic()
        observations.append(executor.collect(target, normalized_config))
    return observations


def load_authorized_scan_target(db: Session, target: ScanJobTarget) -> InventoryScanTarget:
    config = validate_scan_config(target.scan_config)
    inventory_target = _load_inventory_scan_target(db, target)
    # TXT-only domains need no A/AAAA record. Resolve only targets receiving connections.
    if any(name in {"http", "tls", "tcp"} for name in config["executors"]):
        inventory_target = _pin_target(inventory_target)
    return inventory_target


def _load_inventory_scan_target(db: Session, target: ScanJobTarget) -> InventoryScanTarget:
    if target.target_type == ScanTargetTypeEnum.ORGANIZATION:
        organization = db.get(Organization, target.organization_id)
        if organization is None:
            raise ScanExecutorError("Organization target not found")
        if not organization.active or not organization.approved_for_scan:
            raise ScanExecutorError("Organization target is not approved for scanner execution")
        raise ScanExecutorError("Scanner execution requires a concrete DOMAIN or HOST target")

    if target.target_type == ScanTargetTypeEnum.DOMAIN:
        stmt = select(Domain).where(Domain.id == target.domain_id).options(joinedload(Domain.organization))
        domain = db.execute(stmt).unique().scalar_one_or_none()
        if domain is None:
            raise ScanExecutorError("Domain target not found")
        if not domain.active or domain.organization is None or not domain.organization.active:
            raise ScanExecutorError("Domain target is not active")
        if not domain.approved_for_scan:
            raise ScanExecutorError("Domain target is not approved for scanner execution")
        return _build_inventory_target(
            target_type=target.target_type,
            inventory_id=str(domain.id),
            hostname=domain.name,
            connect_host=domain.name,
            domain_name=domain.name,
            allow_sensitive=domain.allow_sensitive_network_scan or domain.organization.allow_sensitive_network_scan,
        )

    if target.target_type == ScanTargetTypeEnum.HOST:
        stmt = (
            select(Host)
            .where(Host.id == target.host_id)
            .options(joinedload(Host.domain).joinedload(Domain.organization))
        )
        host = db.execute(stmt).unique().scalar_one_or_none()
        if host is None:
            raise ScanExecutorError("Host target not found")
        if (
            not host.active
            or host.domain is None
            or not host.domain.active
            or host.domain.organization is None
            or not host.domain.organization.active
        ):
            raise ScanExecutorError("Host target is not active")
        if not host.approved_for_scan:
            raise ScanExecutorError("Host target is not approved for scanner execution")
        return _build_inventory_target(
            target_type=target.target_type,
            inventory_id=str(host.id),
            hostname=host.hostname,
            connect_host=host.ip or host.hostname,
            domain_name=host.domain.name,
            allow_sensitive=(
                host.allow_sensitive_network_scan
                or host.domain.allow_sensitive_network_scan
                or host.domain.organization.allow_sensitive_network_scan
            ),
        )

    raise ScanExecutorError(f"Unsupported scan target type: {target.target_type}")


def _build_inventory_target(
    target_type: ScanTargetTypeEnum,
    inventory_id: str,
    hostname: str,
    connect_host: str,
    domain_name: str,
    allow_sensitive: bool,
) -> InventoryScanTarget:
    hostname = _clean_host_identifier(hostname, "hostname")
    connect_host = _clean_host_identifier(connect_host, "connect_host")
    domain_name = _clean_host_identifier(domain_name, "domain_name")
    inventory_target = InventoryScanTarget(
        target_type=target_type,
        inventory_id=inventory_id,
        hostname=hostname,
        connect_host=connect_host,
        domain_name=domain_name,
        allow_sensitive_network_scan=allow_sensitive,
    )
    return inventory_target


def _clean_host_identifier(value: str, label: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    if not value:
        raise ScanExecutorError(f"{label} is required")
    if "://" in value or "/" in value or "\\" in value or any(ord(char) < 32 for char in value):
        raise ScanExecutorError(f"{label} must be an inventory hostname or IP address, not a URL")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScanExecutorError(f"{label} is not a valid hostname") from exc
        if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
            raise ScanExecutorError(f"{label} is not a valid hostname or IP address")
        return value


def _pin_target(target: InventoryScanTarget) -> InventoryScanTarget:
    addresses = _resolve_addresses(target.connect_host)
    addresses = [address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address for address in addresses]
    if not addresses:
        raise ScanExecutorError("Target has no usable addresses")
    if any(str(address) in METADATA_IPS or address.is_multicast or address.is_unspecified or address.is_link_local for address in addresses):
        raise ScanExecutorError("Metadata, link-local, multicast and unspecified targets are prohibited")
    sensitive = [address for address in addresses if _is_sensitive_address(address)]
    if sensitive and not target.allow_sensitive_network_scan:
        raise ScanExecutorError("Target resolves to sensitive network addresses and is not explicitly approved for them")
    return replace(target, connect_host=str(addresses[0]))


def _resolve_addresses(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        direct_ip = ipaddress.ip_address(hostname)
        return [direct_ip]
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanExecutorError(f"Unable to resolve approved inventory target: {hostname}") from exc
    addresses = sorted({item[4][0] for item in info})
    return [ipaddress.ip_address(address) for address in addresses]


def _is_sensitive_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if str(address) in METADATA_IPS:
        return True
    return (
        address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _same_target_host(hostname: str | None, target: InventoryScanTarget) -> bool:
    if hostname is None:
        return False
    normalized = hostname.lower().rstrip(".")
    return normalized in {target.hostname, target.connect_host}


def _normalize_http_headers(response: http.client.HTTPResponse) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    relevant = {
        "strict-transport-security",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "content-type",
        "location",
    }
    headers: dict[str, list[str]] = {}
    for name, value in response.getheaders():
        lower = name.lower()
        if lower in relevant:
            headers.setdefault(lower, []).append(value.strip())
    cookies = [_redacted_cookie(cookie) for cookie in response.headers.get_all("Set-Cookie", [])]
    return headers, cookies


def _redacted_cookie(header_value: str) -> dict[str, Any]:
    cookie = SimpleCookie()
    try:
        cookie.load(header_value)
    except Exception:
        return {"secure": False, "httponly": False, "parse_error": True}
    morsel = next(iter(cookie.values()), None)
    if morsel is None:
        return {"secure": False, "httponly": False, "parse_error": True}
    return {
        "name_hash": _short_hash(morsel.key),
        "secure": bool(morsel["secure"]),
        "httponly": bool(morsel["httponly"]),
        "samesite": morsel["samesite"] or None,
    }


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _all_cookie_attr(cookies: list[dict[str, Any]], attr: str) -> bool | None:
    if not cookies:
        return None
    return all(bool(cookie.get(attr)) for cookie in cookies)


def _compact_attempt(result: dict[str, Any]) -> dict[str, Any]:
    compact = {
        "endpoint_available": bool(result.get("endpoint_available", False)),
        "status_code": result.get("status_code"),
        "error": result.get("error"),
        "redirect_chain": result.get("redirect_chain", []),
        "request_scheme": result.get("request_scheme"),
        "request_port": result.get("request_port"),
        "request_path": result.get("request_path"),
        "terminal_scheme": result.get("terminal_scheme"),
        "stop_reason": result.get("stop_reason"),
        "headers": result.get("headers", {}),
        "cookies": result.get("cookies", []),
        "content_type": result.get("content_type"),
        "body_sha256": result.get("body_sha256"),
        "body_bytes_captured": result.get("body_bytes_captured"),
        "csp_meta_policies": result.get("csp_meta_policies", []),
        "certificate_trusted": result.get("certificate_trusted"),
        "coverage_declared": bool(result.get("coverage_declared", False)),
    }
    return compact


def _http_to_https_redirect(redirect_chain: list[dict[str, Any]]) -> bool:
    if not redirect_chain:
        return False
    first = redirect_chain[0]
    if first.get("scheme") == "http" and first.get("location_scheme") == "https":
        return True
    return len(redirect_chain) > 1 and first.get("scheme") == "http" and redirect_chain[1].get("scheme") == "https"


def _redirect_chain_contains_insecure_http(redirect_chain: list[dict[str, Any]]) -> bool:
    seen_https = False
    for item in redirect_chain:
        if seen_https and item.get("scheme") == "http":
            return True
        if item.get("scheme") == "https":
            seen_https = True
            if item.get("location_scheme") == "http":
                return True
    return False


def _redirect_chain_mentions_http(redirect_chain: list[dict[str, Any]]) -> bool:
    return any(index > 0 and item.get("scheme") == "http" for index, item in enumerate(redirect_chain)) or any(
        item.get("location_scheme") == "http" for item in redirect_chain
    )


def _header_values(headers: dict[str, Any], name: str) -> list[str]:
    value = headers.get(name.lower())
    if isinstance(value, str):  # Backward-compatible manual/test evidence.
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def _first_header(headers: dict[str, Any], name: str) -> str | None:
    values = _header_values(headers, name)
    return values[0] if values else None


class _CSPMetaParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.policies: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.casefold() != "meta":
            return
        values = {str(name).casefold(): value for name, value in attrs if name}
        if str(values.get("http-equiv", "")).casefold() == "content-security-policy":
            content = values.get("content")
            if isinstance(content, str) and content.strip():
                self.policies.append(content.strip())


def _extract_csp_meta(body: bytes, content_type: str | None) -> list[str]:
    if not content_type or content_type.split(";", 1)[0].strip().casefold() not in {"text/html", "application/xhtml+xml"}:
        return []
    parser = _CSPMetaParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except (ValueError, AssertionError):
        return []
    return parser.policies


def _http_paths_config(config: dict[str, Any]) -> list[str]:
    raw = config.get("http_paths", ["/"])
    if not isinstance(raw, list) or not raw or len(raw) > MAX_HTTP_PATHS:
        raise ScanExecutorError(f"scan_config.http_paths must contain 1 to {MAX_HTTP_PATHS} paths")
    paths: list[str] = []
    for path in raw:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or len(path) > 2048
            or any(ord(char) < 32 for char in path)
            or urlparse(path).scheme
            or urlparse(path).netloc
        ):
            raise ScanExecutorError("scan_config.http_paths contains an invalid same-target path")
        if path not in paths:
            paths.append(path)
    return paths


def _parse_csp(policy: str) -> tuple[dict[str, list[str]] | None, str | None]:
    directives: dict[str, list[str]] = {}
    for raw_directive in policy.split(";"):
        words = raw_directive.strip().split()
        if not words:
            continue
        name = words[0].casefold()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            return None, "invalid_directive_name"
        # CSP ignores later duplicate directives. Preserve that deterministic
        # first-directive behavior instead of merging them into a weaker policy.
        if name not in directives:
            directives[name] = [word.casefold() for word in words[1:]]
    if not directives:
        return None, "empty_policy"
    return directives, None


def _effective_sources(policy: dict[str, list[str]], directive: str) -> list[str] | None:
    fallback = {
        "script-src-elem": ("script-src", "default-src"),
        "script-src": ("default-src",),
        "object-src": ("default-src",),
    }
    if directive in policy:
        return policy[directive]
    for candidate in fallback.get(directive, ()):
        if candidate in policy:
            return policy[candidate]
    return None  # Unrestricted by this policy.


def _policy_allows_token(policy: dict[str, list[str]], directive: str, token: str) -> bool:
    sources = _effective_sources(policy, directive)
    if sources is None:
        return True
    if token not in sources:
        return False
    if token == "'unsafe-inline'" and any(
        source.startswith("'nonce-") or source.startswith("'sha256-")
        or source.startswith("'sha384-") or source.startswith("'sha512-")
        for source in sources
    ):
        return False
    return True


def _policy_allows_broad(policy: dict[str, list[str]], directive: str) -> bool:
    sources = _effective_sources(policy, directive)
    if sources is None:
        return True
    broad = {"*", "http:", "https:", "data:"}
    return any(source in broad for source in sources)


def _csp_state(attempt: dict[str, Any]) -> dict[str, Any]:
    content_type = attempt.get("content_type")
    is_html = isinstance(content_type, str) and content_type.split(";", 1)[0].strip().casefold() in {
        "text/html", "application/xhtml+xml",
    }
    policies = _header_values(attempt.get("headers", {}), "content-security-policy")
    policies += [value for value in attempt.get("csp_meta_policies", []) if isinstance(value, str)]
    parsed = []
    errors = []
    for policy in policies:
        directives, error = _parse_csp(policy)
        parsed.append({
            "sha256": hashlib.sha256(policy.encode("utf-8")).hexdigest(),
            "directives": directives,
            "error": error,
        })
        if error:
            errors.append(error)
    return {"is_html": is_html, "policies": policies, "parsed": parsed, "errors": errors}


def _tri_aggregate(values: list[bool | None]) -> bool | None:
    if any(value is True for value in values):
        return True
    if values and all(value is False for value in values):
        return False
    return None


def _evaluation(
    matched: bool | None,
    reason: str,
    evidence: Any,
    *,
    policy_version: str = WAVE1_POLICY_VERSION,
) -> dict[str, Any]:
    return {
        "matched": matched,
        "outcome": "MATCH" if matched is True else "NO_MATCH" if matched is False else "INDETERMINATE",
        "reason": reason,
        "policy_version": policy_version,
        "evidence": evidence,
    }


def _evaluate_http_wave1(attempts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    header_attempts = [a for a in attempts if a.get("endpoint_available") and a.get("stop_reason") == "terminal_response"]
    csp_results: dict[str, list[bool | None]] = {
        "csp_no_policy_v2": [], "csp_unsafe_policy_v2": [], "csp_too_broad_v2": [],
    }
    hsts_values: list[bool | None] = []
    xcto_values: list[bool | None] = []
    xfo_values: list[bool | None] = []
    details = []
    for attempt in header_attempts:
        headers = attempt.get("headers", {})
        state = _csp_state(attempt)
        detail = {
            "scheme": attempt.get("terminal_scheme"),
            "port": attempt.get("request_port"),
            "path": attempt.get("request_path"),
            "content_type": attempt.get("content_type"),
            "csp": state,
            "coverage_declared": attempt.get("coverage_declared", False),
        }
        details.append(detail)
        if state["is_html"]:
            if state["errors"]:
                missing = unsafe = broad = None
            elif not state["parsed"]:
                missing, unsafe, broad = True, False, False
            else:
                policies = [item["directives"] for item in state["parsed"]]
                missing = False
                unsafe = any(
                    all(_policy_allows_token(policy, directive, token) for policy in policies)
                    for directive, token in (
                        ("script-src", "'unsafe-eval'"),
                        ("script-src", "'unsafe-inline'"),
                        ("script-src-elem", "'unsafe-inline'"),
                    )
                )
                broad = any(
                    all(_policy_allows_broad(policy, directive) for policy in policies)
                    for directive in ("script-src", "script-src-elem", "object-src")
                )
            if missing is True and not attempt.get("coverage_declared"):
                missing = None
            csp_results["csp_no_policy_v2"].append(missing)
            csp_results["csp_unsafe_policy_v2"].append(unsafe)
            csp_results["csp_too_broad_v2"].append(broad)

            xfo = _header_values(headers, "x-frame-options")
            valid_xfo = len(xfo) == 1 and xfo[0].strip().casefold() in {"deny", "sameorigin"}
            restrictive_frame_ancestors = False
            csp_malformed = bool(state["errors"])
            for item in state["parsed"]:
                directives = item["directives"] or {}
                sources = directives.get("frame-ancestors")
                if sources is not None and "*" not in sources:
                    restrictive_frame_ancestors = True
            if valid_xfo or restrictive_frame_ancestors:
                xfo_values.append(False)
            elif csp_malformed:
                xfo_values.append(None)
            elif not xfo and not state["parsed"] and not attempt.get("coverage_declared"):
                xfo_values.append(None)
            else:
                xfo_values.append(True)

        xcto = _header_values(headers, "x-content-type-options")
        xcto_incorrect = not (len(xcto) == 1 and xcto[0].strip().casefold() == "nosniff")
        xcto_values.append(None if not xcto and not attempt.get("coverage_declared") else xcto_incorrect)

        if attempt.get("terminal_scheme") == "https":
            hsts = _header_values(headers, "strict-transport-security")
            hsts_values.append(None if not hsts and not attempt.get("coverage_declared") else _hsts_incorrect(hsts))

    evaluations = {
        key: _evaluation(_tri_aggregate(values), "evaluated declared terminal HTML responses", details)
        for key, values in csp_results.items()
    }
    evaluations["hsts_incorrect_v2"] = _evaluation(
        _tri_aggregate(hsts_values), "evaluated successful HTTPS terminal responses", details,
    )
    evaluations["x_content_type_options_incorrect_v2"] = _evaluation(
        _tri_aggregate(xcto_values), "evaluated successful declared responses", details,
    )
    evaluations["x_frame_options_incorrect_v2"] = _evaluation(
        _tri_aggregate(xfo_values), "evaluated declared terminal HTML responses", details,
    )

    chain_details = [
        {
            "scheme": a.get("request_scheme"), "port": a.get("request_port"), "path": a.get("request_path"),
            "stop_reason": a.get("stop_reason"), "hops": a.get("redirect_chain", []),
            "certificate_trusted": a.get("certificate_trusted"),
        }
        for a in attempts
    ]
    redirect_contains = [_redirect_chain_contains_insecure_http(a.get("redirect_chain", [])) for a in attempts if a.get("redirect_chain")]
    insecure_pattern = [_insecure_redirect_pattern(a) for a in attempts if a.get("redirect_chain")]
    domain_missing = _domain_missing_https(attempts)
    evaluations["redirect_chain_contains_http_v2"] = _evaluation(
        _tri_aggregate(redirect_contains), "evaluated normalized redirect hops", chain_details,
    )
    evaluations["insecure_https_redirect_pattern_v2"] = _evaluation(
        _tri_aggregate(insecure_pattern), "evaluated downgrade, oscillation, and pre-upgrade terminal content", chain_details,
    )
    evaluations["domain_missing_https_v2"] = _evaluation(
        domain_missing, "evaluated HTTP upgrade and trusted HTTPS availability for declared paths", chain_details,
    )
    return evaluations


def _hsts_incorrect(values: list[str]) -> bool:
    if len(values) != 1:
        return True
    directives: dict[str, str | None] = {}
    for item in values[0].split(";"):
        item = item.strip()
        if not item:
            continue
        name, separator, value = item.partition("=")
        name = name.strip().casefold()
        if name in directives:
            return True
        directives[name] = value.strip() if separator else None
    max_age = directives.get("max-age")
    if not isinstance(max_age, str) or not re.fullmatch(r"\d+", max_age):
        return True
    return int(max_age) < 31536000 or "includesubdomains" not in directives


def _insecure_redirect_pattern(attempt: dict[str, Any]) -> bool:
    chain = attempt.get("redirect_chain", [])
    if _redirect_chain_contains_insecure_http(chain):
        return True
    if attempt.get("request_scheme") == "http" and chain:
        first = chain[0]
        # Content or an HTTP-only redirect before an HTTPS upgrade is positive.
        return not (first.get("status_code") in {301, 308} and first.get("location_scheme") == "https")
    return False


def _domain_missing_https(attempts: list[dict[str, Any]]) -> bool | None:
    if attempts and not any(attempt.get("coverage_declared") for attempt in attempts):
        return None
    by_path: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        by_path.setdefault(str(attempt.get("request_path")), []).append(attempt)
    results: list[bool | None] = []
    for path_attempts in by_path.values():
        http = [a for a in path_attempts if a.get("request_scheme") == "http"]
        https = [a for a in path_attempts if a.get("request_scheme") == "https"]
        if not http or not https:
            results.append(None)
            continue
        trusted_https = any(
            a.get("endpoint_available") and a.get("certificate_trusted") is True
            for a in https
        )
        available_http = [a for a in http if a.get("endpoint_available")]
        if available_http:
            upgrades = []
            for attempt in available_http:
                chain = attempt.get("redirect_chain", [])
                upgrades.append(
                    bool(chain)
                    and chain[0].get("status_code") in {301, 308}
                    and chain[0].get("location_scheme") == "https"
                    and attempt.get("terminal_scheme") == "https"
                    and attempt.get("certificate_trusted") is True
                    and attempt.get("stop_reason") == "terminal_response"
                )
            results.append(not all(upgrades))
        elif trusted_https:
            results.append(False)
        elif any(a.get("endpoint_available") for a in https):
            results.append(True)
        else:
            results.append(None)
    return _tri_aggregate(results)


def _certificate_trust(host: str, server_name: str, port: int, timeout: float) -> bool | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except OSError:
        return None


def _certificate_metadata(
    host: str,
    server_name: str,
    port: int,
    timeout: float,
    *,
    trusted_self_signed: set[str] | None = None,
    observation_time: datetime | None = None,
) -> dict[str, Any]:
    observed_at = observation_time or datetime.now(timezone.utc)
    metadata: dict[str, Any] = {
        "endpoint_available": False,
        "observation_time": observed_at.isoformat(),
        "policy_version": WAVE1_POLICY_VERSION,
    }
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                chain_der, chain_capture_complete, chain_source = _served_chain_der(tls)
                certificates = [x509.load_der_x509_certificate(value) for value in chain_der]
                chain = [_certificate_record(cert, index) for index, cert in enumerate(certificates)]
                leaf = certificates[0]
                leaf_record = chain[0]
                lifetime_days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds() / 86400
                metadata.update({
                    "endpoint_available": True,
                    "negotiated_protocol": tls.version(),
                    "certificate_fingerprint_sha256": leaf_record["fingerprint_sha256"],
                    "certificate_not_before": leaf.not_valid_before_utc.isoformat(),
                    "certificate_not_after": leaf.not_valid_after_utc.isoformat(),
                    "certificate_lifetime_days": lifetime_days,
                    "certificate_days_until_expiry": int((leaf.not_valid_after_utc - observed_at).total_seconds() // 86400),
                    "public_key_algorithm": leaf_record["public_key_algorithm"],
                    "public_key_bits": leaf_record["public_key_bits"],
                    "public_key_curve": leaf_record["public_key_curve"],
                    "signature_algorithm": leaf_record["signature_oid"],
                    "signature_hash_algorithm": leaf_record["signature_hash"],
                    "weak_signature_algorithm": leaf_record["weak_signature"],
                    "subject": leaf_record["subject"],
                    "issuer": leaf_record["issuer"],
                    "self_issued": leaf_record["self_issued"],
                    "self_signature_valid": leaf_record["self_signature_valid"],
                    "ocsp_uris": leaf_record["ocsp_uris"],
                    "crl_distribution_uris": leaf_record["crl_distribution_uris"],
                    "certificate_chain": chain,
                    "chain_capture_complete": chain_capture_complete,
                    "chain_capture_source": chain_source,
                })
    except (OSError, ValueError, IndexError, ssl.SSLError) as exc:
        metadata["certificate_error"] = exc.__class__.__name__
        metadata["evaluations"] = _indeterminate_tls_evaluations("TLS handshake or certificate parsing failed")
        return metadata
    trust = _certificate_trust(host, server_name, port, timeout)
    metadata["certificate_trusted"] = trust
    if trust is None:
        metadata["trust_error"] = "trust_validation_unavailable"
    fingerprint = metadata["certificate_fingerprint_sha256"]
    metadata["self_signed_explicitly_trusted"] = fingerprint in (trusted_self_signed or set())
    metadata["trusted_self_signed_policy_hash"] = hashlib.sha256(
        "\n".join(sorted(trusted_self_signed or set())).encode("ascii")
    ).hexdigest()
    metadata["evaluations"] = _evaluate_tls_certificate(metadata, observed_at)
    return metadata


def _served_chain_der(tls: ssl.SSLSocket) -> tuple[list[bytes], bool, str]:
    leaf = tls.getpeercert(binary_form=True)
    if not leaf:
        raise ValueError("missing peer certificate")
    getter = getattr(tls, "get_unverified_chain", None)
    source = "ssl.get_unverified_chain"
    if getter is None and getattr(tls, "_sslobj", None) is not None:
        getter = getattr(tls._sslobj, "get_unverified_chain", None)
        source = "ssl._sslobj.get_unverified_chain"
    if getter is None:
        return [leaf], False, "leaf_only_fallback"
    values = []
    for item in getter() or []:
        if isinstance(item, bytes):
            value = item
        elif hasattr(item, "public_bytes"):
            try:
                value = item.public_bytes()
            except TypeError:
                value = item.public_bytes(serialization.Encoding.DER)
            if isinstance(value, str):
                value = value.encode("ascii")
        else:
            continue
        if value.startswith(b"-----BEGIN"):
            value = x509.load_pem_x509_certificate(value).public_bytes(serialization.Encoding.DER)
        values.append(value)
    if not values:
        return [leaf], False, "leaf_only_fallback"
    return values, True, source


def _certificate_record(cert: x509.Certificate, position: int) -> dict[str, Any]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, bits, curve = "RSA", key.key_size, None
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm, bits, curve = "DSA", key.key_size, None
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm, bits, curve = "EC", key.key_size, key.curve.name
    elif isinstance(key, ed25519.Ed25519PublicKey):
        algorithm, bits, curve = "ED25519", 256, "ed25519"
    elif isinstance(key, ed448.Ed448PublicKey):
        algorithm, bits, curve = "ED448", 448, "ed448"
    else:
        algorithm, bits, curve = "UNKNOWN", None, None
    try:
        hash_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except UnsupportedAlgorithm:
        hash_name = None
    try:
        ocsp = [item.access_location.value for item in cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value if item.access_method == AuthorityInformationAccessOID.OCSP]
    except x509.ExtensionNotFound:
        ocsp = []
    try:
        crl = []
        for point in cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value:
            for name in point.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    crl.append(name.value)
    except x509.ExtensionNotFound:
        crl = []
    self_issued = cert.subject == cert.issuer
    return {
        "position": position,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "public_key_algorithm": algorithm,
        "public_key_bits": bits,
        "public_key_curve": curve,
        "signature_oid": cert.signature_algorithm_oid.dotted_string,
        "signature_hash": hash_name,
        "weak_signature": hash_name in {"md5", "sha1"} if hash_name else None,
        "self_issued": self_issued,
        "self_signature_valid": _verify_self_signature(cert) if self_issued else False,
        "ocsp_uris": sorted(set(ocsp)),
        "crl_distribution_uris": sorted(set(crl)),
    }


def _verify_self_signature(cert: x509.Certificate) -> bool | None:
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            parameters = getattr(cert, "signature_algorithm_parameters", None) or padding.PKCS1v15()
            key.verify(cert.signature, cert.tbs_certificate_bytes, parameters, cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            parameters = getattr(cert, "signature_algorithm_parameters", None) or ec.ECDSA(cert.signature_hash_algorithm)
            key.verify(cert.signature, cert.tbs_certificate_bytes, parameters)
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return None
        return True
    except Exception:
        return False


def _evaluate_tls_certificate(metadata: dict[str, Any], observed_at: datetime) -> dict[str, dict[str, Any]]:
    chain = metadata.get("certificate_chain") or []
    leaf = chain[0] if chain else None
    if not isinstance(leaf, dict):
        return _indeterminate_tls_evaluations("leaf certificate evidence missing")
    expired = datetime.fromisoformat(leaf["not_after"]) < observed_at
    algorithm, bits = leaf.get("public_key_algorithm"), leaf.get("public_key_bits")
    if algorithm in {"RSA", "DSA"} and isinstance(bits, int):
        weak_key: bool | None = bits < 2048
    elif algorithm == "EC" and isinstance(bits, int):
        weak_key = bits < 224
    elif algorithm in {"ED25519", "ED448"}:
        weak_key = False
    else:
        weak_key = None
    weak_values = [item.get("weak_signature") for item in chain]
    if any(value is True for value in weak_values):
        weak_signature: bool | None = True
    elif metadata.get("chain_capture_complete") and weak_values and all(value is False for value in weak_values):
        weak_signature = False
    else:
        weak_signature = None
    self_signed = (
        True if leaf.get("self_issued") is True and leaf.get("self_signature_valid") is True
        else False if leaf.get("self_issued") is False or leaf.get("self_signature_valid") is False
        else None
    )
    if self_signed is True and metadata.get("self_signed_explicitly_trusted"):
        self_signed = False
    lifetime_days = metadata.get("certificate_lifetime_days")
    extension_values_valid = isinstance(leaf.get("ocsp_uris"), list) and isinstance(leaf.get("crl_distribution_uris"), list)
    if not extension_values_valid or self_signed is None or not isinstance(lifetime_days, (int, float)):
        no_revocation: bool | None = None
    elif leaf.get("self_issued") and leaf.get("self_signature_valid"):
        no_revocation = False
    elif lifetime_days <= 7:
        no_revocation = False
    else:
        no_revocation = not leaf["ocsp_uris"] and not leaf["crl_distribution_uris"]
    common = {"leaf_fingerprint_sha256": leaf.get("fingerprint_sha256")}
    return {
        "tlscert_expired": _evaluation(expired, "compared leaf notAfter with observation_time", {**common, "not_after": leaf.get("not_after"), "observation_time": observed_at.isoformat()}),
        "insecure_server_certificate_key_size": _evaluation(weak_key, "applied versioned key-size policy to leaf key", {**common, "algorithm": algorithm, "bits": bits, "curve": leaf.get("public_key_curve")}),
        "tlscert_weak_signature": _evaluation(weak_signature, "applied versioned signature policy to served chain", {"chain": [{"position": item.get("position"), "fingerprint_sha256": item.get("fingerprint_sha256"), "signature_oid": item.get("signature_oid"), "signature_hash": item.get("signature_hash")} for item in chain], "chain_capture_complete": metadata.get("chain_capture_complete")}),
        "tlscert_self_signed": _evaluation(self_signed, "verified leaf self-signature and local fingerprint policy", {**common, "self_issued": leaf.get("self_issued"), "self_signature_valid": leaf.get("self_signature_valid"), "explicitly_trusted": metadata.get("self_signed_explicitly_trusted"), "trust_policy_hash": metadata.get("trusted_self_signed_policy_hash")}),
        "tlscert_no_revocation": _evaluation(no_revocation, "checked leaf OCSP/CRL extensions and short-lived boundary", {**common, "ocsp_uris": leaf.get("ocsp_uris"), "crl_distribution_uris": leaf.get("crl_distribution_uris"), "lifetime_days": lifetime_days, "self_signed": leaf.get("self_issued") and leaf.get("self_signature_valid")}),
    }


def _indeterminate_tls_evaluations(reason: str) -> dict[str, dict[str, Any]]:
    return {
        key: _evaluation(None, reason, {})
        for key in (
            "tlscert_expired", "insecure_server_certificate_key_size", "tlscert_weak_signature",
            "tlscert_self_signed", "tlscert_no_revocation",
        )
    }


def _aggregate_evaluations(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    keys = set().union(*(result.get("evaluations", {}).keys() for result in results))
    aggregated = {}
    for key in keys:
        entries = [result.get("evaluations", {}).get(key) for result in results]
        entries = [entry for entry in entries if isinstance(entry, dict)]
        matched = _tri_aggregate([entry.get("matched") for entry in entries])
        policy_versions = {entry.get("policy_version") for entry in entries}
        policy_version = policy_versions.pop() if len(policy_versions) == 1 else WAVE1_POLICY_VERSION
        aggregated[key] = _evaluation(
            matched, "aggregated configured TLS ports", entries,
            policy_version=policy_version,
        )
    return aggregated


def _fingerprint_allowlist(config: dict[str, Any]) -> set[str]:
    raw = config.get("trusted_self_signed_fingerprints", [])
    if not isinstance(raw, list) or len(raw) > 100:
        raise ScanExecutorError("scan_config.trusted_self_signed_fingerprints must be a list of at most 100 SHA-256 fingerprints")
    values = set()
    for value in raw:
        normalized = str(value).replace(":", "").casefold() if isinstance(value, str) else ""
        if not re.fullmatch(r"[0-9a-f]{64}", normalized):
            raise ScanExecutorError("trusted_self_signed_fingerprints contains an invalid SHA-256 fingerprint")
        values.add(normalized)
    return values


def _tls_version_supported(host: str, server_name: str, port: int, timeout: float, version_name: str) -> bool | None:
    tls_version = getattr(ssl.TLSVersion, version_name, None)
    if tls_version is None:
        return None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = tls_version
            context.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                return True
    except ssl.SSLError as exc:
        return False if exc.reason in {"TLSV1_ALERT_PROTOCOL_VERSION"} else None
    except OSError:
        return None


_TLS_VERSION_NAMES = {
    "TLSv1.0": "TLSv1",
    "TLSv1.1": "TLSv1_1",
    "TLSv1.2": "TLSv1_2",
    "TLSv1.3": "TLSv1_3",
}
_DEFINITIVE_TLS_REJECTIONS = {
    "TLSV1_ALERT_PROTOCOL_VERSION", "SSLV3_ALERT_HANDSHAKE_FAILURE",
    "NO_SHARED_CIPHER", "TLSV1_ALERT_INSUFFICIENT_SECURITY",
    "SSLV3_ALERT_ILLEGAL_PARAMETER", "UNSUPPORTED_PROTOCOL",
}


def _tls_attempt(
    host: str,
    server_name: str,
    port: int,
    timeout: float,
    *,
    version_name: str,
    cipher_name: str | None = None,
) -> dict[str, Any]:
    enum_name = _TLS_VERSION_NAMES[version_name]
    tls_version = getattr(ssl.TLSVersion, enum_name, None)
    result: dict[str, Any] = {
        "offered_version": version_name,
        "offered_cipher": cipher_name,
        "outcome": "INDETERMINATE",
        "accepted": None,
        "negotiated_version": None,
        "negotiated_cipher": None,
        "error_class": None,
        "error_reason": None,
    }
    if tls_version is None:
        result.update(error_class="ClientCapabilityError", error_reason="version_not_supported_by_client")
        return result
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers(f"{cipher_name}:@SECLEVEL=0" if cipher_name else "ALL:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = tls_version
            context.maximum_version = tls_version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                selected = tls.cipher()
                result.update(
                    outcome="ACCEPTED",
                    accepted=True,
                    negotiated_version=tls.version(),
                    negotiated_cipher=selected[0] if selected else None,
                )
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", None) or exc.__class__.__name__
        definitive = reason in _DEFINITIVE_TLS_REJECTIONS
        result.update(
            outcome="REJECTED" if definitive else "INDETERMINATE",
            accepted=False if definitive else None,
            error_class=exc.__class__.__name__,
            error_reason=reason,
        )
    except (OSError, TimeoutError) as exc:
        result.update(error_class=exc.__class__.__name__, error_reason="transport_error")
    return result


def _weak_cipher_catalog() -> tuple[list[dict[str, Any]], str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_ciphers("ALL:@SECLEVEL=0")
    catalog = []
    for cipher in context.get_ciphers():
        if cipher.get("protocol") == "TLSv1.3":
            continue
        symmetric = str(cipher.get("symmetric") or "").casefold()
        description = str(cipher.get("description") or "")
        key_exchange = str(cipher.get("kea") or "").casefold()
        reasons = []
        if int(cipher.get("strength_bits") or 0) < 128:
            reasons.append("effective_strength_below_128")
        if any(token in symmetric for token in ("null", "rc4", "3des", "des", "idea", "seed")):
            reasons.append("disallowed_legacy_or_null_symmetric_primitive")
        if cipher.get("auth") == "auth-null":
            reasons.append("anonymous_authentication")
        if cipher.get("auth") == "auth-dss":
            reasons.append("dsa_authentication")
        if not cipher.get("aead"):
            reasons.append("non_aead_record_protection")
        if "dhe" not in key_exchange:
            reasons.append("no_forward_secret_key_exchange")
        if "Enc=AESCCM8" in description:
            reasons.append("64_bit_authentication_tag")
        if reasons:
            catalog.append({
                "name": cipher["name"],
                "protocol": cipher.get("protocol"),
                "strength_bits": cipher.get("strength_bits"),
                "aead": cipher.get("aead"),
                "symmetric": cipher.get("symmetric"),
                "kea": cipher.get("kea"),
                "auth": cipher.get("auth"),
                "authentication_tag_bits": 64 if "Enc=AESCCM8" in description else None,
                "policy_reasons": reasons,
            })
    catalog.sort(key=lambda item: item["name"])
    digest = hashlib.sha256(repr(catalog).encode("utf-8")).hexdigest()
    return catalog, digest


def _collect_tls_handshake_evidence(host: str, server_name: str, port: int, timeout: float) -> dict[str, Any]:
    protocols = {
        version: _tls_attempt(host, server_name, port, timeout, version_name=version)
        for version in _TLS_VERSION_NAMES
    }
    catalog, catalog_hash = _weak_cipher_catalog()
    offered_names = [cipher["name"] for cipher in catalog]
    cipher_attempts = []
    for version in ("TLSv1.0", "TLSv1.1", "TLSv1.2"):
        protocol_result = protocols[version]
        if protocol_result.get("accepted") is False:
            attempt = {
                "offered_version": version, "offered_ciphers": offered_names,
                "outcome": "PROTOCOL_REJECTED", "accepted": False,
                "negotiated_version": None, "negotiated_cipher": None,
                "error_class": protocol_result.get("error_class"),
                "error_reason": protocol_result.get("error_reason"),
            }
        elif not offered_names:
            attempt = {
                "offered_version": version, "offered_ciphers": [],
                "outcome": "NO_PROHIBITED_CLIENT_SUITES", "accepted": False,
                "negotiated_version": None, "negotiated_cipher": None,
                "error_class": None, "error_reason": None,
            }
        else:
            attempted = _tls_attempt(
                host, server_name, port, timeout,
                version_name=version, cipher_name=":".join(offered_names),
            )
            attempt = {**attempted, "offered_ciphers": offered_names}
            attempt.pop("offered_cipher", None)
        cipher_attempts.append(attempt)
    return {
        "policy_version": WAVE2_TLS_POLICY_VERSION,
        "protocols": protocols,
        "weak_cipher_catalog_hash": catalog_hash,
        "weak_cipher_catalog_complete": False,
        "weak_cipher_coverage_limitation": "runtime OpenSSL provider does not expose every prohibited legacy suite family",
        "weak_cipher_catalog": catalog,
        "weak_cipher_attempts": cipher_attempts,
        "client": {"openssl": ssl.OPENSSL_VERSION, "python_ssl": getattr(ssl, "OPENSSL_VERSION_INFO", None)},
    }


def _evaluate_tls_handshake(observation: dict[str, Any]) -> dict[str, dict[str, Any]]:
    protocols = observation.get("protocols") if isinstance(observation.get("protocols"), dict) else {}
    weak = [protocols.get("TLSv1.0", {}).get("accepted"), protocols.get("TLSv1.1", {}).get("accepted")]
    modern = [protocols.get("TLSv1.2", {}).get("accepted"), protocols.get("TLSv1.3", {}).get("accepted")]
    if any(value is True for value in weak):
        weak_protocol: bool | None = True
    elif all(value is False for value in weak) and any(value is True for value in modern):
        weak_protocol = False
    else:
        weak_protocol = None

    attempts = observation.get("weak_cipher_attempts")
    if isinstance(attempts, list) and any(item.get("accepted") is True for item in attempts):
        weak_cipher = True
    elif not isinstance(attempts, list) or not observation.get("weak_cipher_catalog_complete"):
        weak_cipher = None
    elif attempts and all(item.get("accepted") is False for item in attempts) and any(value is True for value in modern):
        weak_cipher = False
    elif not attempts and any(value is True for value in modern):
        weak_cipher = False
    else:
        weak_cipher = None
    return {
        "tls_weak_protocol": _evaluation(
            weak_protocol, "evaluated completed version-pinned handshakes against the Wave 2 prohibited protocol set",
            {"protocols": protocols, "policy_version": WAVE2_TLS_POLICY_VERSION},
            policy_version=WAVE2_TLS_POLICY_VERSION,
        ),
        "tls_weak_cipher": _evaluation(
            weak_cipher, "offered the complete local policy-prohibited suite set in constrained version-pinned handshakes and required actual server acceptance",
            {"attempts": attempts, "catalog_hash": observation.get("weak_cipher_catalog_hash"), "policy_version": WAVE2_TLS_POLICY_VERSION},
            policy_version=WAVE2_TLS_POLICY_VERSION,
        ),
    }


def _query_txt_records(name: str, server_host: str | None, server_port: int, timeout: float) -> list[str]:
    resolver = dns.resolver.Resolver(configure=server_host is None)
    if server_host:
        resolver.nameservers = [server_host]
    resolver.port = server_port
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, "TXT", search=False, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise ScanExecutorError(f"DNS query failed: {exc.__class__.__name__}") from exc
    return [b"".join(record.strings).decode("utf-8", errors="replace") for record in answer]


def _query_txt_evidence(name: str, server_host: str | None, server_port: int, timeout: float) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "record_type": "TXT", "status": "ERROR", "records": [], "error": None}
    resolver = dns.resolver.Resolver(configure=server_host is None)
    if server_host:
        resolver.nameservers = [server_host]
    resolver.port = server_port
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answer = resolver.resolve(name, "TXT", search=False, raise_on_no_answer=False)
        records = _normalize_txt_records([
            b"".join(record.strings).decode("utf-8", errors="replace") for record in answer
        ])
        result.update(status="ANSWER" if records else "NODATA", records=records)
    except dns.resolver.NXDOMAIN:
        result["status"] = "NXDOMAIN"
    except dns.resolver.NoAnswer:
        result["status"] = "NODATA"
    except dns.exception.DNSException as exc:
        result["error"] = exc.__class__.__name__
    except (OSError, TimeoutError) as exc:
        result["error"] = exc.__class__.__name__
    return result


def _definitive_dns(evidence: dict[str, Any]) -> bool:
    return evidence.get("status") in {"ANSWER", "NODATA", "NXDOMAIN"}


def _spf_records(evidence: dict[str, Any]) -> list[str]:
    return [
        record for record in evidence.get("records", [])
        if re.match(r"^v=spf1(?:\s|$)", record, flags=re.IGNORECASE)
    ]


def _parse_spf_record(record: str) -> dict[str, Any]:
    tokens = record.split()
    parsed: dict[str, Any] = {"record": record, "valid": False, "terms": [], "terminal_all": None, "error": None}
    if not tokens or tokens[0].casefold() != "v=spf1":
        parsed["error"] = "invalid_version"
        return parsed
    redirect_seen = False
    for index, token in enumerate(tokens[1:]):
        if "=" in token and not token.lstrip("+-~?").startswith(("ip4:", "ip6:")):
            name, value = token.split("=", 1)
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", name) or not value or any(char.isspace() for char in value):
                parsed["error"] = "invalid_modifier"
                return parsed
            if name.casefold() == "redirect":
                if redirect_seen:
                    parsed["error"] = "duplicate_redirect"
                    return parsed
                redirect_seen = True
            parsed["terms"].append({"kind": "modifier", "name": name.casefold(), "value": value})
            continue
        qualifier = token[0] if token and token[0] in "+-~?" else "+"
        body = token[1:] if token and token[0] in "+-~?" else token
        match = re.fullmatch(r"([A-Za-z0-9]+)(?::([^/]+))?(?:/(\d{1,3}))?(?://(\d{1,3}))?", body)
        if not match:
            parsed["error"] = "invalid_mechanism_syntax"
            return parsed
        name, argument, cidr4, cidr6 = match.groups()
        name = name.casefold()
        if name not in {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}:
            parsed["error"] = "unknown_mechanism"
            return parsed
        if name in {"include", "exists", "ip4", "ip6"} and not argument:
            parsed["error"] = "missing_mechanism_argument"
            return parsed
        if name == "all" and (argument or cidr4 or cidr6):
            parsed["error"] = "all_has_argument"
            return parsed
        try:
            if name == "ip4":
                ipaddress.IPv4Network(argument + (f"/{cidr4}" if cidr4 else ""), strict=False)
            elif name == "ip6":
                ipaddress.IPv6Network(argument + (f"/{cidr4}" if cidr4 else ""), strict=False)
            elif cidr4 and int(cidr4) > 32:
                raise ValueError
            elif cidr6 and int(cidr6) > 128:
                raise ValueError
        except ValueError:
            parsed["error"] = "invalid_network_or_cidr"
            return parsed
        term = {"kind": "mechanism", "name": name, "qualifier": qualifier, "argument": argument, "position": index}
        parsed["terms"].append(term)
    mechanisms = [term for term in parsed["terms"] if term["kind"] == "mechanism"]
    if mechanisms and mechanisms[-1]["name"] == "all":
        parsed["terminal_all"] = mechanisms[-1]["qualifier"]
    parsed["valid"] = True
    return parsed


def _analyze_spf(
    domain: str,
    root: dict[str, Any],
    server_host: str | None,
    server_port: int,
    timeout: float,
) -> dict[str, Any]:
    analysis: dict[str, Any] = {
        "domain": domain, "record_count": 0, "records": [], "valid": None,
        "permanent_error": None, "error_class": None, "lookup_count": 0,
        "lookup_trace": [], "terminal_all": None,
    }
    if not _definitive_dns(root):
        analysis["error_class"] = "dns_unavailable"
        return analysis
    records = _spf_records(root)
    analysis["record_count"] = len(records)
    if not records:
        analysis.update(valid=False, permanent_error=False, error_class="record_missing")
        return analysis
    if len(records) > 1:
        analysis.update(valid=False, permanent_error=True, error_class="multiple_spf_records")
        return analysis
    parsed = _parse_spf_record(records[0])
    analysis["records"] = [parsed]
    analysis["terminal_all"] = parsed.get("terminal_all")
    if not parsed["valid"]:
        analysis.update(valid=False, permanent_error=True, error_class=parsed["error"])
        return analysis
    if any(
        "%" in str(term.get("argument") or term.get("value") or "")
        for term in parsed["terms"]
        if term.get("name") in {"include", "redirect", "a", "mx", "exists"}
    ):
        analysis.update(valid=None, permanent_error=None, error_class="macro_expansion_not_observable")
        return analysis
    visited = {domain.casefold()}
    pending = [(domain, parsed)]
    while pending:
        source_domain, current = pending.pop()
        for term in current["terms"]:
            lookup_domain = None
            if term["kind"] == "mechanism" and term["name"] in {"include", "a", "mx", "ptr", "exists"}:
                analysis["lookup_count"] += 1
                lookup_domain = term.get("argument")
            elif term["kind"] == "modifier" and term["name"] == "redirect":
                analysis["lookup_count"] += 1
                lookup_domain = term["value"]
            else:
                continue
            analysis["lookup_trace"].append({"source": source_domain, "term": term, "lookup_number": analysis["lookup_count"]})
            if analysis["lookup_count"] > 10:
                analysis.update(valid=False, permanent_error=True, error_class="dns_lookup_limit_exceeded")
                return analysis
            if term.get("name") not in {"include", "redirect"}:
                continue
            if not lookup_domain or "%" in lookup_domain:
                analysis.update(valid=None, permanent_error=None, error_class="macro_expansion_not_observable")
                return analysis
            normalized = lookup_domain.casefold().rstrip(".")
            if normalized in visited:
                analysis.update(valid=False, permanent_error=True, error_class="include_redirect_loop")
                return analysis
            visited.add(normalized)
            nested_evidence = _query_txt_evidence(normalized, server_host, server_port, timeout)
            analysis["lookup_trace"][-1]["dns"] = nested_evidence
            if not _definitive_dns(nested_evidence):
                analysis.update(valid=None, permanent_error=None, error_class="nested_dns_unavailable")
                return analysis
            nested_records = _spf_records(nested_evidence)
            if len(nested_records) != 1:
                analysis.update(valid=False, permanent_error=True, error_class="nested_spf_record_count")
                return analysis
            nested = _parse_spf_record(nested_records[0])
            if not nested["valid"]:
                analysis.update(valid=False, permanent_error=True, error_class=nested["error"])
                return analysis
            pending.append((normalized, nested))
    analysis.update(valid=True, permanent_error=False)
    return analysis


def _analyze_dmarc(evidence: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"record_count": 0, "valid": None, "tags": {}, "error": None, "effective_policy": None}
    if not _definitive_dns(evidence):
        result["error"] = "dns_unavailable"
        return result
    records = [record for record in evidence.get("records", []) if record.casefold().startswith("v=dmarc1")]
    result["record_count"] = len(records)
    if not records:
        result.update(valid=False, error="record_missing")
        return result
    if len(records) > 1:
        result.update(valid=False, error="multiple_dmarc_records")
        return result
    pairs = [part.strip() for part in records[0].split(";") if part.strip()]
    tags = {}
    for index, pair in enumerate(pairs):
        if "=" not in pair:
            result.update(valid=False, error="invalid_tag")
            return result
        name, value = (part.strip().casefold() for part in pair.split("=", 1))
        if not re.fullmatch(r"[a-z][a-z0-9]*", name) or not value or name in tags:
            result.update(valid=False, error="invalid_or_duplicate_tag")
            return result
        if index == 0 and (name != "v" or value != "dmarc1"):
            result.update(valid=False, error="version_not_first")
            return result
        tags[name] = value
    if tags.get("v") != "dmarc1" or tags.get("p") not in {"none", "quarantine", "reject"}:
        result.update(valid=False, tags=tags, error="missing_or_invalid_policy")
        return result
    if "sp" in tags and tags["sp"] not in {"none", "quarantine", "reject"}:
        result.update(valid=False, tags=tags, error="invalid_subdomain_policy")
        return result
    if "pct" in tags:
        try:
            if not 0 <= int(tags["pct"]) <= 100:
                raise ValueError
        except ValueError:
            result.update(valid=False, tags=tags, error="invalid_percentage")
            return result
    result.update(valid=True, tags=tags, effective_policy=tags["p"])
    return result


def _evaluate_email_security(
    domain: str,
    root_txt: dict[str, Any],
    spf: dict[str, Any],
    dmarc_txt: dict[str, Any],
    dmarc: dict[str, Any],
    nonce_queries: list[dict[str, Any]],
    subdomain_dmarc: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not _definitive_dns(root_txt):
        missing_spf: bool | None = None
    else:
        missing_spf = not bool(_spf_records(root_txt))
    malformed_spf = spf.get("permanent_error") if spf.get("error_class") != "record_missing" else False
    if spf.get("valid") is True:
        if dmarc.get("valid") is True:
            percentage = int(dmarc.get("tags", {}).get("pct", "100"))
            mitigated = dmarc.get("effective_policy") in {"quarantine", "reject"} and percentage > 0
            softfail: bool | None = spf.get("terminal_all") == "~" and not mitigated
        elif dmarc.get("error") == "record_missing":
            softfail = spf.get("terminal_all") == "~"
        else:
            softfail = None
    elif spf.get("error_class") == "record_missing":
        softfail = False
    else:
        softfail = None
    nonce_spf = [_spf_records(item) for item in nonce_queries]
    if all(_definitive_dns(item) for item in nonce_queries):
        if all(values for values in nonce_spf) and nonce_spf[0] == nonce_spf[1]:
            wildcard: bool | None = True
        elif all(not values for values in nonce_spf):
            wildcard = False
        else:
            wildcard = None
    else:
        wildcard = None
    if not _definitive_dns(dmarc_txt):
        dmarc_missing: bool | None = None
    else:
        dmarc_missing = dmarc.get("error") == "record_missing"
    dmarc_none = dmarc.get("effective_policy") == "none" if dmarc.get("valid") is True else None

    sub_results = []
    for item in subdomain_dmarc:
        direct = _analyze_dmarc(item["query"])
        if direct.get("valid") is True:
            policy = direct["effective_policy"]
        elif direct.get("error") == "record_missing" and dmarc.get("valid") is True:
            policy = dmarc["tags"].get("sp", dmarc["effective_policy"])
        else:
            policy = None
        sub_results.append({"subdomain": item["subdomain"], "direct": direct, "effective_policy": policy})
    if not sub_results or any(item["effective_policy"] is None for item in sub_results):
        subdomain_none: bool | None = None
    else:
        subdomain_none = any(item["effective_policy"] == "none" for item in sub_results)
    common = {"domain": domain, "policy_version": WAVE2_EMAIL_POLICY_VERSION}
    return {
        "spf_record_missing": _evaluation(missing_spf, "checked the exact declared-domain TXT response for v=spf1", {**common, "query": root_txt}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
        "spf_record_malformed": _evaluation(malformed_spf, "parsed and recursively bounded the single SPF policy", {**common, "analysis": spf}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
        "spf_record_softfail": _evaluation(softfail, "combined a valid terminal ~all with the observable effective DMARC policy", {**common, "spf": spf, "dmarc": dmarc}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
        "spf_record_wildcard": _evaluation(wildcard, "compared SPF answers at two unpredictable nonce subdomains", {**common, "queries": nonce_queries}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
        "dmarc_record_missing": _evaluation(dmarc_missing, "checked exact _dmarc TXT evidence for the declared organizational domain", {**common, "query": dmarc_txt, "analysis": dmarc}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
        "dmarc_contains_none": _evaluation(dmarc_none, "parsed the single applicable DMARC record and effective p policy", {**common, "analysis": dmarc}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
        "subdomain_dmarc_contains_none": _evaluation(subdomain_none, "evaluated direct or inherited policy only for explicitly declared subdomains", {**common, "subdomains": sub_results}, policy_version=WAVE2_EMAIL_POLICY_VERSION),
    }


def validate_scan_config(config: dict[str, Any] | None) -> dict[str, Any]:
    if config is not None and not isinstance(config, dict):
        raise ScanExecutorError("scan_config must be an object")
    config = dict(config or {})
    names = config.get(
        "executors",
        ["http", "tls", "dns"] + (["tcp"] if config.get("tcp_ports") or config.get("service_probes") else []),
    )
    if not isinstance(names, list) or not names or not all(isinstance(name, str) and name.lower() in EXECUTOR_BY_NAME for name in names):
        raise ScanExecutorError("scan_config.executors must contain supported executor names")
    config["executors"] = list(dict.fromkeys(name.lower() for name in names))
    if config.get("dns_server_host") is not None:
        if not isinstance(config["dns_server_host"], str):
            raise ScanExecutorError("dns_server_host must be a hostname or IP address")
        config["dns_server_host"] = _clean_host_identifier(config["dns_server_host"], "dns_server_host")
    for key, default, count in (("http_ports", [80], MAX_HTTP_PORTS), ("https_ports", [443], MAX_HTTP_PORTS), ("tls_ports", [443], MAX_TLS_PORTS), ("tcp_ports", [], MAX_TCP_PORTS)):
        ports = _ports_config(config, key, default, count)
        if key == "tls_ports" and "tls" in config["executors"] and not ports:
            raise ScanExecutorError("tls_ports must not be empty")
    if "http" in config["executors"] and not (_ports_config(config, "http_ports", [80], MAX_HTTP_PORTS) or _ports_config(config, "https_ports", [443], MAX_HTTP_PORTS)):
        raise ScanExecutorError("HTTP execution requires at least one configured HTTP or HTTPS port")
    if "http" in config["executors"]:
        _http_paths_config(config)
    if "tls" in config["executors"]:
        _fingerprint_allowlist(config)
    if "dns" in config["executors"]:
        raw_subdomains = config.get("email_subdomains", [])
        if not isinstance(raw_subdomains, list) or len(raw_subdomains) > 20:
            raise ScanExecutorError("scan_config.email_subdomains must be a list of at most 20 declared subdomains")
        if not all(isinstance(value, str) for value in raw_subdomains):
            raise ScanExecutorError("scan_config.email_subdomains must contain hostnames")
        config["email_subdomains"] = [
            _clean_host_identifier(value, "email_subdomain") for value in raw_subdomains
        ]
    for key, default, low, high in (("request_timeout_seconds", 5., .1, 30.), ("connect_timeout_seconds", 3., .1, 15.), ("dns_timeout_seconds", 3., .1, 15.), ("per_target_interval_seconds", .05, 0., 2.)):
        _float_config(config, key, default, low, high)
    _float_config(config, "service_probe_timeout_seconds", config.get("connect_timeout_seconds", 3.), .1, 15.)
    for key, default, low, high in (("redirect_limit", 5, 0, 10), ("response_size_limit_bytes", 65536, 1024, 262144), ("dns_server_port", 53, 1, 65535), ("tls_port", 443, 1, 65535)):
        _int_config(config, key, default, low, high)
    _int_config(config, "service_probe_response_limit_bytes", 4096, 64, MAX_SERVICE_PROBE_RESPONSE_BYTES)
    config["service_probes"] = _service_probes_config(config)
    return config


def _service_probes_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    raw = config.get("service_probes", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list) or len(raw) > MAX_SERVICE_PROBES:
        raise ScanExecutorError(f"scan_config.service_probes must be a list of at most {MAX_SERVICE_PROBES} probes")
    normalized = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) - {"protocol", "port", "transport"}:
            raise ScanExecutorError("each service probe must contain only protocol, port and optional transport")
        protocol = item.get("protocol")
        port = item.get("port")
        transport = item.get("transport", "tcp")
        if not isinstance(protocol, str) or protocol.lower() not in SERVICE_PROBE_ADAPTERS:
            raise ScanExecutorError("service probe protocol is unsupported")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ScanExecutorError("service probe port must be an integer from 1 to 65535")
        if not isinstance(transport, str) or not transport or len(transport) > 16:
            raise ScanExecutorError("service probe transport must be a short string")
        value = {"protocol": protocol.lower(), "port": port, "transport": transport.lower()}
        identity = (value["protocol"], port, value["transport"])
        if identity not in seen:
            normalized.append(value)
            seen.add(identity)
    return normalized


def _email_subdomains_config(config: dict[str, Any], organizational_domain: str) -> list[str]:
    raw = config.get("email_subdomains", [])
    if not isinstance(raw, list) or len(raw) > 20:
        raise ScanExecutorError("scan_config.email_subdomains must be a list of at most 20 declared subdomains")
    values = []
    suffix = "." + organizational_domain.casefold().rstrip(".")
    for value in raw:
        if not isinstance(value, str):
            raise ScanExecutorError("scan_config.email_subdomains must contain hostnames")
        normalized = _clean_host_identifier(value, "email_subdomain")
        if not normalized.endswith(suffix):
            raise ScanExecutorError("email_subdomain must be strictly beneath the declared organizational domain")
        if normalized not in values:
            values.append(normalized)
    return values


def _normalize_txt_records(records: list[str]) -> list[str]:
    return sorted(record.strip() for record in records if record and record.strip())


def _ports_config(config: dict[str, Any], key: str, default: list[int], max_ports: int) -> list[int]:
    raw = config.get(key, default)
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ScanExecutorError(f"scan_config.{key} must be a list of ports")
    ports: list[int] = []
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 65535:
            raise ScanExecutorError(f"scan_config.{key} contains an invalid port")
        if value not in ports:
            ports.append(value)
    if len(ports) > max_ports:
        raise ScanExecutorError(f"scan_config.{key} exceeds the maximum allowed ports")
    return ports


def _int_config(config: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise ScanExecutorError(f"scan_config.{key} must be an integer from {minimum} to {maximum}")
    return value


def _float_config(config: dict[str, Any], key: str, default: float, minimum: float, maximum: float) -> float:
    value = config.get(key, default)
    if isinstance(value, bool):
        raise ScanExecutorError(f"scan_config.{key} must be a finite number")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value) or value < minimum or value > maximum:
        raise ScanExecutorError(f"scan_config.{key} must be a number from {minimum} to {maximum}")
    return value
