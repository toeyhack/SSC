"""Bounded RFC 7208 permanent-error analysis for ``spf_record_malformed``.

This module deliberately does not expose SPF sender-authorization results.
PASS/other authorization states exist only as internal control-flow markers so
that the analyzer can determine whether later terms remain reachable.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from dataclasses import dataclass, replace
from typing import Any, Callable


SPF_PARSER_VERSION = "ssc-wave4b-spf-parser.v1"
SPF_POLICY_VERSION = "ssc-wave4b-spf-malformed-policy.v1"

RFC_DNS_TERM_LIMIT = 10
RFC_VOID_LOOKUP_LIMIT = 2
RFC_MX_HOST_LIMIT = 10
MAX_LOGICAL_DNS_QUERIES = 256
MAX_ELAPSED_SECONDS = 20.0
MAX_DNS_RESPONSE_BYTES = 16 * 1024
MAX_SPF_RECORD_BYTES = 8 * 1024
MAX_ABSTRACT_STATES = 64
MAX_EVALUATOR_STEPS = 512
MAX_QUERY_TRACE = 256

DEFINITIVE_DNS = {"ANSWER", "NODATA", "NXDOMAIN"}
UNCERTAIN_DNS = {
    "TIMEOUT", "SERVFAIL", "REFUSED", "FORMERR",
    "TRUNCATED_OR_MALFORMED", "OPERATIONAL_LIMIT", "ERROR",
}
DNS_TERMS = {"include", "a", "mx", "ptr", "exists", "redirect"}
MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
DEFINED_MODIFIERS = {"redirect", "exp"}
RUNTIME_MACROS = {"s", "l", "o", "i", "p", "h", "v"}
MACRO_DELIMITERS = ".-+,/_="
_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9._-]*")
_TOPLABEL_RE = re.compile(r"(?=.{1,63}\.?$)(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.?$")


@dataclass(frozen=True)
class SPFAnalysisLimits:
    dns_terms: int = RFC_DNS_TERM_LIMIT
    void_lookups: int = RFC_VOID_LOOKUP_LIMIT
    mx_hosts: int = RFC_MX_HOST_LIMIT
    logical_queries: int = MAX_LOGICAL_DNS_QUERIES
    elapsed_seconds: float = MAX_ELAPSED_SECONDS
    response_bytes: int = MAX_DNS_RESPONSE_BYTES
    record_bytes: int = MAX_SPF_RECORD_BYTES
    abstract_states: int = MAX_ABSTRACT_STATES
    evaluator_steps: int = MAX_EVALUATOR_STEPS
    query_trace: int = MAX_QUERY_TRACE


@dataclass(frozen=True)
class MacroToken:
    kind: str
    value: str
    letter: str | None = None
    digits: int | None = None
    reverse: bool = False
    delimiters: str = ""
    uppercase: bool = False


@dataclass(frozen=True)
class SPFTerm:
    kind: str
    name: str
    position: int
    raw: str
    qualifier: str = "+"
    argument: str | None = None
    cidr4: int | None = None
    cidr6: int | None = None
    macro_tokens: tuple[MacroToken, ...] = ()

    def evidence(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "kind": self.kind, "name": self.name, "position": self.position,
        }
        if self.kind == "mechanism":
            value["qualifier"] = self.qualifier
        if self.argument is not None:
            value["argument"] = self.argument
        if self.cidr4 is not None:
            value["cidr4"] = self.cidr4
        if self.cidr6 is not None:
            value["cidr6"] = self.cidr6
        return value


@dataclass(frozen=True)
class ParsedSPF:
    valid: bool
    record: str
    terms: tuple[SPFTerm, ...] = ()
    error_code: str | None = None
    terminal_all: str | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "record": self.record,
            "valid": self.valid,
            "terms": [term.evidence() for term in self.terms],
            "terminal_all": self.terminal_all,
            "error": self.error_code,
            "parser_version": SPF_PARSER_VERSION,
        }


@dataclass(frozen=True)
class Branch:
    family: str
    dns_terms: int = 0
    void_lookups: int = 0


@dataclass(frozen=True)
class Terminal:
    kind: str  # PASS, OTHER, PERMERROR, INDETERMINATE
    branch: Branch
    reason: str


QueryFunction = Callable[[str, str, float], dict[str, Any]]


def selected_spf_records(evidence: dict[str, Any]) -> list[str]:
    """Select SPF1 records without trimming or treating generic whitespace as SP."""
    return [
        value for value in evidence.get("records", [])
        if isinstance(value, str) and _has_spf1_prefix(value)
    ]


def _has_spf1_prefix(value: str) -> bool:
    return len(value) >= 6 and value[:6].casefold() == "v=spf1" and (len(value) == 6 or value[6] == " ")


def _selected_invalid_records(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in evidence.get("invalid_records", []) if item.get("spf1_prefix") is True]


def parse_spf_record(record: str) -> ParsedSPF:
    """Parse and validate the complete selected SPF record before evaluation."""
    try:
        encoded = record.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return ParsedSPF(False, record, error_code="non_ascii_spf_record")
    if len(encoded) > MAX_SPF_RECORD_BYTES:
        return ParsedSPF(False, record, error_code="record_operational_limit")
    if any(char.isspace() and char != " " for char in record):
        return ParsedSPF(False, record, error_code="non_sp_whitespace")
    if not _has_spf1_prefix(record):
        return ParsedSPF(False, record, error_code="invalid_version")
    if len(record) > 6 and record[6] != " ":
        return ParsedSPF(False, record, error_code="invalid_version_separator")

    raw_terms = [value for value in record[6:].split(" ") if value]
    terms: list[SPFTerm] = []
    seen_defined: set[str] = set()
    terminal_all: str | None = None
    for position, raw in enumerate(raw_terms):
        parsed, error = _parse_term(raw, position)
        if error:
            return ParsedSPF(False, record, tuple(terms), error_code=error, terminal_all=terminal_all)
        assert parsed is not None
        if parsed.kind == "modifier" and parsed.name in DEFINED_MODIFIERS:
            if parsed.name in seen_defined:
                return ParsedSPF(False, record, tuple(terms), error_code=f"duplicate_{parsed.name}", terminal_all=terminal_all)
            seen_defined.add(parsed.name)
        if parsed.kind == "mechanism" and parsed.name == "all" and terminal_all is None:
            terminal_all = parsed.qualifier
        terms.append(parsed)
    return ParsedSPF(True, record, tuple(terms), terminal_all=terminal_all)


def _parse_term(raw: str, position: int) -> tuple[SPFTerm | None, str | None]:
    qualifier = "+"
    body = raw
    if body and body[0] in "+-~?":
        qualifier, body = body[0], body[1:]
        if not body:
            return None, "missing_mechanism"

    name_match = _NAME_RE.match(body)
    if not name_match:
        return None, "invalid_term_name"
    name = name_match.group(0).casefold()
    remainder = body[name_match.end():]

    if qualifier == "+" and raw[0] not in "+-~?" and remainder.startswith("="):
        value = remainder[1:]
        if name in DEFINED_MODIFIERS:
            if not value:
                return None, f"empty_{name}"
            macro_tokens, error = _parse_macro_string(value, domain_spec=True)
        else:
            macro_tokens, error = _parse_macro_string(value, domain_spec=False)
        if error:
            return None, error
        return SPFTerm("modifier", name, position, raw, argument=value, macro_tokens=macro_tokens), None

    if name not in MECHANISMS:
        return None, "unknown_mechanism"
    if remainder.startswith("="):
        return None, "mechanism_uses_equals"

    if name == "all":
        if remainder:
            return None, "all_has_argument"
        return SPFTerm("mechanism", name, position, raw, qualifier=qualifier), None

    if name in {"include", "exists"}:
        if not remainder.startswith(":") or len(remainder) == 1:
            return None, "missing_mechanism_argument"
        argument = remainder[1:]
        tokens, error = _parse_macro_string(argument, domain_spec=True)
        if error:
            return None, error
        return SPFTerm("mechanism", name, position, raw, qualifier, argument, macro_tokens=tokens), None

    if name == "ptr":
        if not remainder:
            return SPFTerm("mechanism", name, position, raw, qualifier), None
        if not remainder.startswith(":") or len(remainder) == 1:
            return None, "invalid_ptr_syntax"
        argument = remainder[1:]
        tokens, error = _parse_macro_string(argument, domain_spec=True)
        if error:
            return None, error
        return SPFTerm("mechanism", name, position, raw, qualifier, argument, macro_tokens=tokens), None

    if name in {"ip4", "ip6"}:
        if not remainder.startswith(":") or len(remainder) == 1:
            return None, "missing_mechanism_argument"
        value = remainder[1:]
        if "//" in value:
            return None, "invalid_network_or_cidr"
        address, slash, cidr_text = value.partition("/")
        try:
            if name == "ip4":
                ipaddress.IPv4Address(address)
                maximum = 32
            else:
                ipaddress.IPv6Address(address)
                maximum = 128
            cidr = _parse_cidr(cidr_text, maximum) if slash else maximum
        except ValueError:
            return None, "invalid_network_or_cidr"
        return SPFTerm(
            "mechanism", name, position, raw, qualifier, address,
            cidr4=cidr if name == "ip4" else None,
            cidr6=cidr if name == "ip6" else None,
        ), None

    # a and mx have an optional domain-spec followed by optional dual CIDR.
    argument, cidr4_text, cidr6_text, error = _split_dual_cidr(remainder)
    if error:
        return None, error
    if argument is not None:
        tokens, error = _parse_macro_string(argument, domain_spec=True)
        if error:
            return None, error
    else:
        tokens = ()
    try:
        cidr4 = _parse_cidr(cidr4_text, 32) if cidr4_text is not None else None
        cidr6 = _parse_cidr(cidr6_text, 128) if cidr6_text is not None else None
    except ValueError:
        return None, "invalid_network_or_cidr"
    return SPFTerm("mechanism", name, position, raw, qualifier, argument, cidr4, cidr6, tokens), None


def _split_dual_cidr(remainder: str) -> tuple[str | None, str | None, str | None, str | None]:
    argument: str | None = None
    suffix = remainder
    if suffix.startswith(":"):
        body = suffix[1:]
        split_at = _first_unbraced_slash(body)
        if split_at is None:
            argument, suffix = body, ""
        else:
            argument, suffix = body[:split_at], body[split_at:]
        if not argument:
            return None, None, None, "empty_domain_spec"
    elif suffix and not suffix.startswith("/"):
        return None, None, None, "invalid_mechanism_syntax"

    if not suffix:
        return argument, None, None, None
    match = re.fullmatch(r"(?:/([0-9]+))?(?://([0-9]+))?", suffix)
    if not match or suffix == "/":
        return None, None, None, "invalid_dual_cidr"
    return argument, match.group(1), match.group(2), None


def _first_unbraced_slash(value: str) -> int | None:
    inside = False
    index = 0
    while index < len(value):
        if value.startswith("%{", index):
            inside = True
            index += 2
            continue
        if inside and value[index] == "}":
            inside = False
        elif not inside and value[index] == "/":
            return index
        index += 1
    return None


def _parse_cidr(value: str, maximum: int) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError
    number = int(value)
    if number > maximum:
        raise ValueError
    return number


def _parse_macro_string(value: str, *, domain_spec: bool) -> tuple[tuple[MacroToken, ...], str | None]:
    tokens: list[MacroToken] = []
    literal: list[str] = []

    def flush() -> None:
        if literal:
            tokens.append(MacroToken("literal", "".join(literal)))
            literal.clear()

    index = 0
    while index < len(value):
        char = value[index]
        if ord(char) < 0x21 or ord(char) > 0x7E:
            return (), "invalid_macro_literal"
        if char != "%":
            literal.append(char)
            index += 1
            continue
        flush()
        if index + 1 >= len(value):
            return (), "invalid_macro_escape"
        next_char = value[index + 1]
        if next_char in "%_-":
            tokens.append(MacroToken("escape", "%" + next_char))
            index += 2
            continue
        if next_char != "{":
            return (), "invalid_macro_escape"
        end = value.find("}", index + 2)
        if end < 0:
            return (), "unterminated_macro"
        content = value[index + 2:end]
        match = re.fullmatch(r"([A-Za-z])([0-9]*)([rR]?)([.\-+,/_=]*)", content)
        if not match or match.group(1).casefold() not in "slodiphcrtv":
            return (), "invalid_macro"
        letter = match.group(1).casefold()
        if letter in {"c", "r", "t"}:
            return (), "exp_only_macro_in_domain_spec"
        digits_text = match.group(2)
        if digits_text and int(digits_text) == 0:
            return (), "zero_macro_transformer"
        tokens.append(MacroToken(
            "macro", value[index:end + 1], letter=letter,
            digits=int(digits_text) if digits_text else None,
            reverse=bool(match.group(3)), delimiters=match.group(4),
            uppercase=match.group(1).isupper(),
        ))
        index = end + 1
    flush()

    if domain_spec:
        if not value:
            return (), "empty_domain_spec"
        last = tokens[-1] if tokens else None
        if last is None:
            return (), "empty_domain_spec"
        if last.kind == "literal":
            candidate = last.value
            without_dot = candidate[:-1] if candidate.endswith(".") else candidate
            top = without_dot.rsplit(".", 1)[-1]
            if "." not in without_dot or not _TOPLABEL_RE.fullmatch(top):
                return (), "invalid_domain_spec"
        elif last.kind == "escape":
            # Syntactically allowed as macro-expand; resulting DNS validity is
            # checked after expansion and may be indeterminate under RFC 7208.
            pass
    return tuple(tokens), None


def expand_supported_domain(tokens: tuple[MacroToken, ...], domain: str) -> tuple[str | None, str | None]:
    parts: list[str] = []
    for token in tokens:
        if token.kind == "literal":
            parts.append(token.value)
        elif token.kind == "escape":
            parts.append({"%%": "%", "%_": " ", "%-": "%20"}[token.value])
        elif token.letter != "d":
            return None, "runtime_context_missing"
        else:
            value = _transform_macro_value(domain, token)
            if token.uppercase:
                value = _url_escape(value)
            parts.append(value)
    expanded = "".join(parts)
    if len(expanded) > 253:
        labels = expanded.split(".")
        while labels and len(".".join(labels)) > 253:
            labels.pop(0)
        expanded = ".".join(labels)
    expanded = expanded.rstrip(".")
    if not _valid_dns_target(expanded):
        return None, "undefined_expanded_domain"
    return expanded.casefold(), None


def _transform_macro_value(value: str, token: MacroToken) -> str:
    delimiters = token.delimiters or "."
    pieces = re.split("[" + re.escape(delimiters) + "]+", value)
    if token.digits is not None:
        pieces = pieces[-token.digits:]
    if token.reverse:
        pieces.reverse()
    return ".".join(pieces)


def _url_escape(value: str) -> str:
    unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(char if char in unreserved else "%{:02X}".format(ord(char)) for char in value)


def _valid_dns_target(value: str) -> bool:
    if not value or len(value) > 253 or ".." in value:
        return False
    labels = value.split(".")
    return all(
        0 < len(label.encode("ascii", errors="strict")) <= 63
        and re.fullmatch(r"[A-Za-z0-9_-]+", label) is not None
        for label in labels
    )


class SPFAnalyzer:
    def __init__(
        self,
        domain: str,
        root: dict[str, Any],
        query: QueryFunction,
        *,
        limits: SPFAnalysisLimits | None = None,
        started_at: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.domain = domain.casefold().rstrip(".")
        self.root = root
        self.query = query
        self.limits = limits or SPFAnalysisLimits()
        self.clock = clock
        self.started_at = clock() if started_at is None else started_at
        self.query_count = 1
        self.steps = 0
        self.cache: dict[tuple[str, str], dict[str, Any]] = {}
        self.trace: list[dict[str, Any]] = [self._query_summary(root)]
        self.visited_hashes: set[str] = set()
        self.loop_observed = False
        self.max_depth = 0
        self.max_dns_terms = 0
        self.max_voids = 0
        self.operational_stop_reason: str | None = None

    def analyze(self) -> dict[str, Any]:
        if self.clock() - self.started_at >= self.limits.elapsed_seconds:
            self.operational_stop_reason = "elapsed_time_limit"
            return self._result("INDETERMINATE", self.operational_stop_reason, selected_count=0)
        status = self.root.get("status", "ERROR")
        if status not in DEFINITIVE_DNS:
            if status == "OPERATIONAL_LIMIT":
                self.operational_stop_reason = self.root.get("error_class") or "root_operational_limit"
            return self._result(
                "INDETERMINATE",
                self.operational_stop_reason or "root_dns_unavailable",
                selected_count=0,
            )
        records = selected_spf_records(self.root)
        invalid = _selected_invalid_records(self.root)
        selected_count = len(records) + len(invalid)
        if selected_count == 0:
            return self._result("NO_MATCH", "record_missing", selected_count=0)
        if selected_count > 1:
            return self._result("MATCH", "multiple_spf_records", selected_count=selected_count)
        if invalid:
            return self._result("MATCH", "non_ascii_spf_record", selected_count=1,
                                record_hash=invalid[0].get("sha256"), record_length=invalid[0].get("octet_length"))

        record = records[0]
        encoded = record.encode("ascii", errors="strict")
        record_hash = hashlib.sha256(encoded).hexdigest()
        if len(encoded) > self.limits.record_bytes:
            self.operational_stop_reason = "spf_record_size_limit"
            return self._result("INDETERMINATE", self.operational_stop_reason, selected_count=1,
                                record=record, record_hash=record_hash, record_length=len(encoded))
        parsed = parse_spf_record(record)
        if not parsed.valid:
            if parsed.error_code == "record_operational_limit":
                self.operational_stop_reason = "spf_record_size_limit"
                outcome = "INDETERMINATE"
            else:
                outcome = "MATCH"
            return self._result(outcome, parsed.error_code or "syntax_error", selected_count=1,
                                record=record, record_hash=record_hash, record_length=len(encoded), parsed=parsed)

        self.visited_hashes.add(record_hash)
        initial = [Branch("ipv4"), Branch("ipv6")]
        terminals = self._evaluate_record(self.domain, parsed, initial, (self.domain,), 0)
        terminals = self._dedupe_terminals(terminals)
        kinds = {terminal.kind for terminal in terminals}
        if kinds == {"PERMERROR"}:
            outcome = "MATCH"
            reason = sorted({terminal.reason for terminal in terminals})[0]
        elif kinds and kinds <= {"PASS", "OTHER"}:
            outcome = "NO_MATCH"
            reason = "complete_without_permerror"
        else:
            outcome = "INDETERMINATE"
            reason = self.operational_stop_reason or "mixed_or_incomplete_branches"
        return self._result(
            outcome, reason, selected_count=1, record=record, record_hash=record_hash,
            record_length=len(encoded), parsed=parsed, terminals=terminals,
        )

    def _evaluate_record(
        self,
        domain: str,
        parsed: ParsedSPF,
        branches: list[Branch],
        active_path: tuple[str, ...],
        depth: int,
    ) -> list[Terminal]:
        self.max_depth = max(self.max_depth, depth)
        current = branches
        terminals: list[Terminal] = []
        mechanisms = [term for term in parsed.terms if term.kind == "mechanism"]
        redirect = next((term for term in parsed.terms if term.kind == "modifier" and term.name == "redirect"), None)
        has_all = any(term.name == "all" for term in mechanisms)
        for term in mechanisms:
            if not current:
                break
            next_branches: list[Branch] = []
            for branch in current:
                if not self._step():
                    terminals.append(Terminal("INDETERMINATE", branch, self.operational_stop_reason or "step_limit"))
                    continue
                matched, continued, exceptional = self._evaluate_mechanism(
                    domain, term, branch, active_path, depth,
                )
                terminals.extend(exceptional)
                terminals.extend(Terminal(self._qualified_result(term.qualifier), item, f"matched_{term.name}") for item in matched)
                next_branches.extend(continued)
            current = self._bounded_branches(next_branches, terminals)
            if term.name == "all":
                current = []
                break

        if current and redirect is not None and not has_all:
            for branch in current:
                terminals.extend(self._evaluate_redirect(domain, redirect, branch, active_path, depth))
            current = []
        terminals.extend(Terminal("OTHER", branch, "implicit_neutral") for branch in current)
        return terminals

    def _evaluate_mechanism(
        self,
        domain: str,
        term: SPFTerm,
        branch: Branch,
        active_path: tuple[str, ...],
        depth: int,
    ) -> tuple[list[Branch], list[Branch], list[Terminal]]:
        if term.name == "all":
            return [branch], [], []
        if term.name in {"ip4", "ip6"}:
            target_family = "ipv4" if term.name == "ip4" else "ipv6"
            if branch.family != target_family:
                return [], [branch], []
            prefix = term.cidr4 if term.name == "ip4" else term.cidr6
            if prefix == 0:
                return [branch], [], []
            return [branch], [branch], []

        counted, error = self._count_dns_term(branch)
        if error:
            return [], [], [Terminal("PERMERROR", counted, error)]
        branch = counted
        if term.name == "ptr":
            return [], [], [Terminal("INDETERMINATE", branch, "runtime_context_missing_ptr")]

        target, expansion_error = self._term_target(domain, term)
        if expansion_error:
            return [], [], [Terminal("INDETERMINATE", branch, expansion_error)]
        assert target is not None

        if term.name == "include":
            nested = self._evaluate_nested(target, branch, active_path, depth + 1, include=True)
            matched = [item.branch for item in nested if item.kind == "PASS"]
            continued = [item.branch for item in nested if item.kind == "OTHER"]
            exceptional = [item for item in nested if item.kind in {"PERMERROR", "INDETERMINATE"}]
            return matched, continued, exceptional
        if term.name == "exists":
            result, branch = self._lookup_with_void(target, "A", branch)
            return self._simple_dns_match(result, branch, term.name)
        if term.name == "a":
            rrtype = "A" if branch.family == "ipv4" else "AAAA"
            result, branch = self._lookup_with_void(target, rrtype, branch)
            return self._address_match(result, branch, term.name)
        if term.name == "mx":
            return self._evaluate_mx(target, branch)
        return [], [], [Terminal("INDETERMINATE", branch, "unsupported_mechanism_state")]

    def _evaluate_mx(self, target: str, branch: Branch) -> tuple[list[Branch], list[Branch], list[Terminal]]:
        mx_result, branch = self._lookup_with_void(target, "MX", branch)
        status = mx_result.get("status")
        if status not in DEFINITIVE_DNS:
            return [], [], [Terminal("INDETERMINATE", branch, "mx_dns_unavailable")]
        hosts = [str(value).casefold().rstrip(".") for value in mx_result.get("records", [])]
        if not hosts:
            return [], [branch], []
        if len(hosts) > self.limits.mx_hosts:
            return [], [], [Terminal("PERMERROR", branch, "mx_host_limit_exceeded")]
        rrtype = "A" if branch.family == "ipv4" else "AAAA"
        possible_match = False
        current = branch
        exceptional: list[Terminal] = []
        for host in hosts:
            result, current = self._lookup_with_void(host, rrtype, current)
            if current.void_lookups > self.limits.void_lookups:
                exceptional.append(Terminal("PERMERROR", current, "void_lookup_limit_exceeded"))
                return ([current] if possible_match else []), [], exceptional
            if result.get("status") not in DEFINITIVE_DNS:
                exceptional.append(Terminal("INDETERMINATE", current, "mx_address_dns_unavailable"))
                return ([current] if possible_match else []), [], exceptional
            if result.get("status") == "ANSWER" and int(result.get("answer_count", len(result.get("records", [])))) > 0:
                possible_match = True
        return ([current] if possible_match else []), [current], exceptional

    def _simple_dns_match(
        self, result: dict[str, Any], branch: Branch, name: str,
    ) -> tuple[list[Branch], list[Branch], list[Terminal]]:
        if branch.void_lookups > self.limits.void_lookups:
            return [], [], [Terminal("PERMERROR", branch, "void_lookup_limit_exceeded")]
        if result.get("status") not in DEFINITIVE_DNS:
            return [], [], [Terminal("INDETERMINATE", branch, f"{name}_dns_unavailable")]
        count = int(result.get("answer_count", len(result.get("records", []))))
        return ([branch], [], []) if result.get("status") == "ANSWER" and count > 0 else ([], [branch], [])

    def _address_match(
        self, result: dict[str, Any], branch: Branch, name: str,
    ) -> tuple[list[Branch], list[Branch], list[Terminal]]:
        if branch.void_lookups > self.limits.void_lookups:
            return [], [], [Terminal("PERMERROR", branch, "void_lookup_limit_exceeded")]
        if result.get("status") not in DEFINITIVE_DNS:
            return [], [], [Terminal("INDETERMINATE", branch, f"{name}_dns_unavailable")]
        count = int(result.get("answer_count", len(result.get("records", []))))
        if result.get("status") == "ANSWER" and count > 0:
            return [branch], [branch], []
        return [], [branch], []

    def _evaluate_redirect(
        self,
        domain: str,
        term: SPFTerm,
        branch: Branch,
        active_path: tuple[str, ...],
        depth: int,
    ) -> list[Terminal]:
        branch, error = self._count_dns_term(branch)
        if error:
            return [Terminal("PERMERROR", branch, error)]
        target, expansion_error = self._term_target(domain, term)
        if expansion_error:
            return [Terminal("INDETERMINATE", branch, expansion_error)]
        assert target is not None
        return self._evaluate_nested(target, branch, active_path, depth + 1, include=False)

    def _evaluate_nested(
        self,
        target: str,
        branch: Branch,
        active_path: tuple[str, ...],
        depth: int,
        *,
        include: bool,
    ) -> list[Terminal]:
        if target in active_path:
            self.loop_observed = True
        result, branch = self._lookup_with_void(target, "TXT", branch)
        if branch.void_lookups > self.limits.void_lookups:
            return [Terminal("PERMERROR", branch, "void_lookup_limit_exceeded")]
        if result.get("status") not in DEFINITIVE_DNS:
            return [Terminal("INDETERMINATE", branch, "nested_dns_unavailable")]
        records = selected_spf_records(result)
        invalid = _selected_invalid_records(result)
        count = len(records) + len(invalid)
        if count == 0:
            return [Terminal("PERMERROR", branch, "include_missing_spf" if include else "redirect_missing_spf")]
        if count > 1:
            return [Terminal("PERMERROR", branch, "nested_multiple_spf_records")]
        if invalid:
            return [Terminal("PERMERROR", branch, "nested_non_ascii_spf_record")]
        record = records[0]
        encoded = record.encode("ascii", errors="strict")
        if len(encoded) > self.limits.record_bytes:
            self.operational_stop_reason = "spf_record_size_limit"
            return [Terminal("INDETERMINATE", branch, self.operational_stop_reason)]
        parsed = parse_spf_record(record)
        if not parsed.valid:
            if parsed.error_code == "record_operational_limit":
                self.operational_stop_reason = "spf_record_size_limit"
                return [Terminal("INDETERMINATE", branch, self.operational_stop_reason)]
            return [Terminal("PERMERROR", branch, parsed.error_code or "nested_syntax_error")]
        self.visited_hashes.add(hashlib.sha256(encoded).hexdigest())
        return self._evaluate_record(target, parsed, [branch], active_path + (target,), depth)

    def _term_target(self, domain: str, term: SPFTerm) -> tuple[str | None, str | None]:
        if term.argument is None:
            return domain, None
        return expand_supported_domain(term.macro_tokens, domain)

    def _count_dns_term(self, branch: Branch) -> tuple[Branch, str | None]:
        branch = replace(branch, dns_terms=branch.dns_terms + 1)
        self.max_dns_terms = max(self.max_dns_terms, branch.dns_terms)
        if branch.dns_terms > self.limits.dns_terms:
            return branch, "dns_term_limit_exceeded"
        return branch, None

    def _lookup_with_void(self, name: str, rrtype: str, branch: Branch) -> tuple[dict[str, Any], Branch]:
        result = self._lookup(name, rrtype)
        if result.get("status") in {"NODATA", "NXDOMAIN"}:
            branch = replace(branch, void_lookups=branch.void_lookups + 1)
            self.max_voids = max(self.max_voids, branch.void_lookups)
        return result, branch

    def _lookup(self, name: str, rrtype: str) -> dict[str, Any]:
        key = (name.casefold().rstrip("."), rrtype.upper())
        if key in self.cache:
            return self.cache[key]
        elapsed = self.clock() - self.started_at
        if elapsed >= self.limits.elapsed_seconds:
            self.operational_stop_reason = "elapsed_time_limit"
            return {"name": key[0], "record_type": key[1], "status": "OPERATIONAL_LIMIT", "error_class": self.operational_stop_reason}
        if self.query_count >= self.limits.logical_queries:
            self.operational_stop_reason = "logical_query_limit"
            return {"name": key[0], "record_type": key[1], "status": "OPERATIONAL_LIMIT", "error_class": self.operational_stop_reason}
        if len(self.trace) >= self.limits.query_trace:
            self.operational_stop_reason = "query_trace_limit"
            return {"name": key[0], "record_type": key[1], "status": "OPERATIONAL_LIMIT", "error_class": self.operational_stop_reason}
        self.query_count += 1
        remaining = max(0.001, self.limits.elapsed_seconds - elapsed)
        result = self.query(key[0], key[1], remaining)
        if result.get("status") == "OPERATIONAL_LIMIT":
            self.operational_stop_reason = result.get("error_class") or "dns_operational_limit"
        if int(result.get("response_size", 0) or 0) > self.limits.response_bytes:
            result = {
                "name": key[0], "record_type": key[1], "status": "OPERATIONAL_LIMIT",
                "records": [], "answer_count": 0, "response_size": result.get("response_size"),
                "error_class": "dns_response_size_limit",
            }
            self.operational_stop_reason = "dns_response_size_limit"
        self.cache[key] = result
        self.trace.append(self._query_summary(result))
        return result

    def _step(self) -> bool:
        self.steps += 1
        if self.steps > self.limits.evaluator_steps:
            self.operational_stop_reason = "evaluator_step_limit"
            return False
        return True

    def _bounded_branches(self, branches: list[Branch], terminals: list[Terminal]) -> list[Branch]:
        values = sorted(set(branches), key=lambda item: (item.family, item.dns_terms, item.void_lookups))
        if len(values) > self.limits.abstract_states:
            self.operational_stop_reason = "abstract_state_limit"
            terminals.extend(Terminal("INDETERMINATE", branch, self.operational_stop_reason) for branch in values)
            return []
        return values

    @staticmethod
    def _qualified_result(qualifier: str) -> str:
        return "PASS" if qualifier == "+" else "OTHER"

    @staticmethod
    def _dedupe_terminals(terminals: list[Terminal]) -> list[Terminal]:
        unique = {(item.kind, item.branch, item.reason): item for item in terminals}
        return sorted(unique.values(), key=lambda item: (item.kind, item.branch.family, item.branch.dns_terms, item.branch.void_lookups, item.reason))

    @staticmethod
    def _answer_hash(evidence: dict[str, Any]) -> str | None:
        values = evidence.get("records", [])
        invalid = evidence.get("invalid_records", [])
        if not values and not invalid:
            return None
        canonical = "\n".join(sorted(str(value) for value in values)) + "\n" + "\n".join(
            sorted(str(item.get("sha256")) for item in invalid)
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _query_summary(self, evidence: dict[str, Any]) -> dict[str, Any]:
        status = evidence.get("status", "ERROR")
        return {
            "name": evidence.get("name"),
            "type": evidence.get("record_type", "TXT"),
            "status": status,
            "error_class": evidence.get("error_class") or evidence.get("error"),
            "response_size": evidence.get("response_size"),
            "answer_count": int(evidence.get("answer_count", len(evidence.get("records", []))) or 0),
            "answer_hash": self._answer_hash(evidence),
            "void": status in {"NODATA", "NXDOMAIN"},
        }

    def _result(
        self,
        outcome: str,
        reason: str,
        *,
        selected_count: int,
        record: str | None = None,
        record_hash: str | None = None,
        record_length: int | None = None,
        parsed: ParsedSPF | None = None,
        terminals: list[Terminal] | None = None,
    ) -> dict[str, Any]:
        elapsed_ms = max(0, int((self.clock() - self.started_at) * 1000))
        permanent_reason = reason if outcome == "MATCH" else None
        return {
            "domain": self.domain,
            "record_count": selected_count,
            "records": [parsed.evidence()] if parsed is not None else [],
            "valid": False if outcome == "MATCH" or selected_count == 0 else True if outcome == "NO_MATCH" else None,
            "permanent_error": True if outcome == "MATCH" else False if outcome == "NO_MATCH" else None,
            "error_class": reason,
            "terminal_all": parsed.terminal_all if parsed is not None else None,
            "lookup_count": self.max_dns_terms,
            "void_lookup_count": self.max_voids,
            "lookup_trace": self.trace,
            "parser": {
                "version": SPF_PARSER_VERSION,
                "status": "VALID" if parsed is not None and parsed.valid else "INVALID" if parsed is not None else "NOT_APPLICABLE",
                "error_code": parsed.error_code if parsed is not None else None,
                "term_count": len(parsed.terms) if parsed is not None else 0,
                "terminal_all": parsed.terminal_all if parsed is not None else None,
            },
            "record": {
                "selected_count": selected_count,
                "normalized_spf": record,
                "sha256": record_hash,
                "octet_length": record_length,
            },
            "limits": {
                "dns_terms": self.max_dns_terms,
                "void_lookups": self.max_voids,
                "logical_queries": self.query_count,
                "max_recursion_depth": self.max_depth,
                "elapsed_ms": elapsed_ms,
                "configured": {
                    "dns_terms": self.limits.dns_terms,
                    "void_lookups": self.limits.void_lookups,
                    "mx_hosts": self.limits.mx_hosts,
                    "logical_queries": self.limits.logical_queries,
                    "elapsed_seconds": self.limits.elapsed_seconds,
                    "response_bytes": self.limits.response_bytes,
                    "record_bytes": self.limits.record_bytes,
                    "abstract_states": self.limits.abstract_states,
                    "evaluator_steps": self.limits.evaluator_steps,
                    "query_trace": self.limits.query_trace,
                },
            },
            "traversal": {
                "complete": outcome != "INDETERMINATE",
                "visited_record_hashes": sorted(self.visited_hashes),
                "queries": self.trace,
                "loop_observed": self.loop_observed,
                "permanent_error_reason": permanent_reason,
                "operational_stop_reason": self.operational_stop_reason,
                "terminal_states": sorted({item.kind for item in terminals or []}),
            },
            "evaluator": {
                "policy_version": SPF_POLICY_VERSION,
                "outcome": outcome,
                "reason": reason,
            },
            "outcome": outcome,
            "policy_version": SPF_POLICY_VERSION,
        }


def analyze_spf(
    domain: str,
    root: dict[str, Any],
    query: QueryFunction,
    *,
    limits: SPFAnalysisLimits | None = None,
    started_at: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    return SPFAnalyzer(domain, root, query, limits=limits, started_at=started_at, clock=clock).analyze()
