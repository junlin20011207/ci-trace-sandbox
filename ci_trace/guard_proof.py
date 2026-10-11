"""Narrow, non-evaluating proof of a repository-origin guard."""
import re
TARGET = re.compile(r"^github\.event\.workflow_run\.head_repository\.full_name\s*==\s*github\.repository$")
def origin_guard_proved(value):
    expr = str(value or "").strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2].strip()
    if not expr or "||" in expr or "!" in expr:
        return False
    if any(x in expr for x in ("(", ")", "{", "}", ";", "$")):
        return False
    terms = [term.strip() for term in expr.split("&&")]
    return any(TARGET.fullmatch(term) for term in terms)
