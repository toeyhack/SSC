"""Deterministic evidence evaluation; no network, database or output dependencies."""
import re
from typing import Any


class RuleEvaluationError(ValueError):
    pass


def evaluate_rule_expression(expression: dict[str, Any], evidence: dict[str, Any]) -> bool:
    operator = expression.get("operator")
    path = expression.get("path")
    if not isinstance(operator, str):
        raise RuleEvaluationError("rule_expression.operator must be a string")
    if not isinstance(path, str):
        raise RuleEvaluationError("rule_expression.path must be a string")

    found, value = _extract_path(evidence, path)
    if operator == "exists":
        return found
    if operator == "missing":
        return not found
    if operator == "equals":
        return found and value == expression.get("value")
    if operator == "not_equals":
        return (not found) or value != expression.get("value")
    if operator == "contains":
        expected = expression.get("value")
        if isinstance(value, list):
            return expected in value
        if isinstance(value, str) and isinstance(expected, str):
            return expected in value
        return False
    if operator == "regex":
        pattern = expression.get("pattern")
        if not isinstance(value, str) or not isinstance(pattern, str):
            return False
        return re.search(pattern, value) is not None
    raise RuleEvaluationError(f"Unsupported rule_expression.operator: {operator}")


def _extract_path(evidence: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = evidence
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
            continue
        if isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
            continue
        return False, None
    return True, current
