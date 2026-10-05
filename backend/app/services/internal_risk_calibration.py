"""Reviewed internal scoring metadata for supported SSC issue observations.

This registry is independent of imported SSC taxonomy metadata.  In particular,
SSC severity is never an input to internal risk resolution.
"""
from dataclasses import dataclass


CALIBRATION_NAME = "ssc-supported-internal-risk"
CALIBRATION_VERSION = "1.2"


@dataclass(frozen=True)
class InternalRiskDecision:
    breach_risk: str
    affects_score: bool


def _decision(breach_risk: str, affects_score: bool = True) -> InternalRiskDecision:
    return InternalRiskDecision(breach_risk=breach_risk, affects_score=affects_score)


# Exact approved decisions from docs/INTERNAL_RISK_CALIBRATION_V1.csv.
SSC_SUPPORTED_INTERNAL_RISK_V1 = {
    "csp_no_policy_v2": _decision("LOW"),
    "csp_too_broad_v2": _decision("LOW"),
    "csp_unsafe_policy_v2": _decision("LOW"),
    "domain_missing_https_v2": _decision("MEDIUM"),
    "hsts_incorrect_v2": _decision("LOW"),
    "insecure_https_redirect_pattern_v2": _decision("MEDIUM"),
    "insecure_server_certificate_key_size": _decision("MEDIUM"),
    "redirect_chain_contains_http_v2": _decision("MEDIUM"),
    "x_content_type_options_incorrect_v2": _decision("LOW"),
    "x_frame_options_incorrect_v2": _decision("LOW"),
    "dmarc_contains_none": _decision("LOW"),
    "dmarc_record_missing": _decision("LOW"),
    "spf_record_missing": _decision("LOW"),
    "spf_record_softfail": _decision("LOW"),
    "spf_record_wildcard": _decision("UNKNOWN", False),
    "subdomain_dmarc_contains_none": _decision("LOW"),
    "service_redis": _decision("LOW"),
    "service_rsync": _decision("UNKNOWN", False),
    "service_smb": _decision("LOW"),
    "service_socks_proxy": _decision("UNKNOWN", False),
    "service_telnet": _decision("LOW"),
    "service_vnc": _decision("LOW"),
    "tls_weak_protocol": _decision("MEDIUM"),
    "tlscert_expired": _decision("LOW"),
    "tlscert_no_revocation": _decision("UNKNOWN", False),
    "tlscert_self_signed": _decision("LOW"),
    "tlscert_weak_signature": _decision("MEDIUM"),
    "unsafe_sri_v2": _decision("LOW"),
    "insecure_ftp": _decision("LOW"),
    "contact_information_detected": _decision("UNKNOWN", False),
    "local_file_path_exposed_via_url_scheme": _decision("LOW"),
    "server_error": _decision("UNKNOWN", False),
    "links_to_insecure_website": _decision("LOW"),
    "service_soap": _decision("UNKNOWN", False),
    "ssh_weak_protocol": _decision("MEDIUM"),
    "ssh_weak_cipher": _decision("LOW"),
    "ssh_weak_mac": _decision("LOW"),
}


UNCONFIGURED_SSC_INTERNAL_RISK = InternalRiskDecision(
    breach_risk="UNKNOWN",
    affects_score=False,
)


def resolve_ssc_internal_risk(issue_key: str) -> InternalRiskDecision:
    """Return explicit SSC internal risk, failing closed when it is unconfigured."""
    return SSC_SUPPORTED_INTERNAL_RISK_V1.get(issue_key, UNCONFIGURED_SSC_INTERNAL_RISK)
