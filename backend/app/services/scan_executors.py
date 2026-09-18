import http.client
import ipaddress
import socket
import ssl
import time
import math
import re
import warnings

import dns.resolver
from cryptography import x509
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.models.models import Domain, Host, Organization
from app.models.scan_models import EvidenceSourceEnum, ScanJobTarget, ScanTargetTypeEnum


USER_AGENT = "InternalSecurityRatingScanner/Phase4B"
METADATA_IPS = {"169.254.169.254", "100.100.100.200"}
MAX_HTTP_PORTS = 4
MAX_TCP_PORTS = 10
MAX_TLS_PORTS = 3


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

        attempts: list[dict[str, Any]] = []
        selected: dict[str, Any] | None = None
        for scheme, ports in (("http", http_ports), ("https", https_ports)):
            for port in ports:
                result = self._request_chain(target, scheme, port, timeout, redirect_limit, response_size_limit, set(http_ports), set(https_ports))
                attempts.append(_compact_attempt(result))
                if result.get("endpoint_available") and (selected is None or (scheme == "https" and not result.get("error"))):
                    selected = result

        if selected is None and attempts:
            selected = attempts[0]
        selected = selected or {}
        headers = selected.get("headers") if isinstance(selected.get("headers"), dict) else {}
        cookies = selected.get("cookies") if isinstance(selected.get("cookies"), list) else []
        redirect_chain = selected.get("redirect_chain") if isinstance(selected.get("redirect_chain"), list) else []

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
            "redirect_chain": redirect_chain,
            "http_to_https_redirect": any(_http_to_https_redirect(attempt["redirect_chain"]) for attempt in attempts),
            "redirect_chain_contains_insecure_http": any(_redirect_chain_contains_insecure_http(attempt["redirect_chain"]) for attempt in attempts),
            "hsts_present": ("strict-transport-security" in headers) if redirect_chain and redirect_chain[-1].get("scheme") == "https" else None,
            "csp_present": "content-security-policy" in headers,
            "x_content_type_options_present": "x-content-type-options" in headers,
            "clickjacking_protection_present": (
                "x-frame-options" in headers or "frame-ancestors" in headers.get("content-security-policy", "").lower()
            ),
            "cookies": cookies,
            "all_cookies_secure": _all_cookie_attr(cookies, "secure"),
            "all_cookies_httponly": _all_cookie_attr(cookies, "httponly"),
            "attempts": attempts,
        }
        if selected.get("error"):
            evidence["error"] = selected["error"]
            evidence["status"] = "error"
        return ExecutorObservation(self.evidence_source, evidence)

    def _request_chain(
        self,
        target: InventoryScanTarget,
        scheme: str,
        port: int,
        timeout: float,
        redirect_limit: int,
        response_size_limit: int,
        http_ports: set[int],
        https_ports: set[int],
    ) -> dict[str, Any]:
        url_hostname = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
        url = f"{scheme}://{url_hostname}:{port}/"
        redirect_chain: list[dict[str, Any]] = []
        current_url = url
        last_result: dict[str, Any] = {
            "endpoint_available": False,
            "status_code": None,
            "headers": {},
            "cookies": [],
            "redirect_chain": redirect_chain,
        }

        for _ in range(redirect_limit + 1):
            parsed = urlparse(current_url)
            if parsed.scheme not in {"http", "https"}:
                last_result["error"] = f"unsupported redirect scheme: {parsed.scheme}"
                return last_result
            if not _same_target_host(parsed.hostname, target):
                last_result["error"] = "redirect target is outside approved inventory target"
                return last_result

            try:
                port_number = parsed.port or (443 if parsed.scheme == "https" else 80)
            except ValueError:
                last_result["error"] = "invalid redirect port"
                return last_result
            if port_number not in (https_ports if parsed.scheme == "https" else http_ports):
                last_result["error"] = "redirect port is outside configured scan ports"
                return last_result
            if parsed.username is not None or parsed.password is not None:
                last_result["error"] = "redirect credentials are not allowed"
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
                return last_result

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
                }
            )
            last_result = {**result, "redirect_chain": redirect_chain}

            if result["status_code"] not in {301, 302, 303, 307, 308} or not location:
                return last_result
            current_url = urljoin(current_url, str(location))

        last_result["error"] = "redirect limit exceeded"
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
            response.read(response_size_limit)
            normalized_headers, cookies = _normalize_http_headers(response)
            return {
                "endpoint_available": True,
                "status_code": response.status,
                "headers": normalized_headers,
                "cookies": cookies,
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
        results = []
        for port in ports:
            metadata = _certificate_metadata(target.connect_host, target.hostname, port, timeout)
            available = metadata.get("endpoint_available", False)
            result = {
                "port": port,
                **metadata,
                "tls10_supported": _tls_version_supported(target.connect_host, target.hostname, port, timeout, "TLSv1") if available else None,
                "tls11_supported": _tls_version_supported(target.connect_host, target.hostname, port, timeout, "TLSv1_1") if available else None,
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

        error = None
        try:
            spf_records = _query_txt_records(domain, server_host, server_port, timeout)
            dmarc_records = _query_txt_records(f"_dmarc.{domain}", server_host, server_port, timeout)
        except (OSError, TimeoutError, ScanExecutorError) as exc:
            spf_records = []
            dmarc_records = []
            error = exc.__class__.__name__
        spf_records = _normalize_txt_records(spf_records)
        dmarc_records = _normalize_txt_records(dmarc_records)
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
        if not ports:
            evidence["skipped"] = "no tcp_ports configured"
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
        if normalized_config.get("tcp_ports"):
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


def _normalize_http_headers(response: http.client.HTTPResponse) -> tuple[dict[str, str], list[dict[str, Any]]]:
    relevant = {
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "location",
    }
    headers: dict[str, str] = {}
    for name, value in response.getheaders():
        lower = name.lower()
        if lower in relevant:
            headers[lower] = value.strip()
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
    return {
        "endpoint_available": bool(result.get("endpoint_available", False)),
        "status_code": result.get("status_code"),
        "error": result.get("error"),
        "redirect_chain": result.get("redirect_chain", []),
    }


def _http_to_https_redirect(redirect_chain: list[dict[str, Any]]) -> bool:
    if not redirect_chain:
        return False
    first = redirect_chain[0]
    if first.get("scheme") == "http" and first.get("location_scheme") == "https":
        return True
    return len(redirect_chain) > 1 and first.get("scheme") == "http" and redirect_chain[1].get("scheme") == "https"


def _redirect_chain_contains_insecure_http(redirect_chain: list[dict[str, Any]]) -> bool:
    return any(index > 0 and item.get("scheme") == "http" for index, item in enumerate(redirect_chain)) or any(
        item.get("location_scheme") == "http" for item in redirect_chain
    )


def _certificate_metadata(host: str, server_name: str, port: int, timeout: float) -> dict[str, Any]:
    metadata: dict[str, Any] = {"endpoint_available": False}
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name) as tls:
                cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
                metadata.update({
                    "endpoint_available": True,
                    "negotiated_protocol": tls.version(),
                    "certificate_not_after": cert.not_valid_after_utc.isoformat(),
                    "certificate_days_until_expiry": int((cert.not_valid_after_utc - datetime.now(timezone.utc)).total_seconds() // 86400),
                    "public_key_bits": getattr(cert.public_key(), "key_size", None),
                    "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
                    "weak_signature_algorithm": cert.signature_hash_algorithm is not None and cert.signature_hash_algorithm.name in {"md5", "sha1"},
                })
    except (OSError, ValueError) as exc:
        metadata["certificate_error"] = exc.__class__.__name__
        return metadata
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_name):
                metadata["certificate_trusted"] = True
    except ssl.SSLCertVerificationError:
        metadata["certificate_trusted"] = False
    except OSError as exc:
        metadata["certificate_trusted"] = None
        metadata["trust_error"] = exc.__class__.__name__
    return metadata


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


def validate_scan_config(config: dict[str, Any] | None) -> dict[str, Any]:
    if config is not None and not isinstance(config, dict):
        raise ScanExecutorError("scan_config must be an object")
    config = dict(config or {})
    names = config.get("executors", ["http", "tls", "dns"] + (["tcp"] if config.get("tcp_ports") else []))
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
    for key, default, low, high in (("request_timeout_seconds", 5., .1, 30.), ("connect_timeout_seconds", 3., .1, 15.), ("dns_timeout_seconds", 3., .1, 15.), ("per_target_interval_seconds", .05, 0., 2.)):
        _float_config(config, key, default, low, high)
    for key, default, low, high in (("redirect_limit", 5, 0, 10), ("response_size_limit_bytes", 65536, 1024, 262144), ("dns_server_port", 53, 1, 65535), ("tls_port", 443, 1, 65535)):
        _int_config(config, key, default, low, high)
    return config


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
