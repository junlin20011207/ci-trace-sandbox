"""Conservative proof checks for a *narrow* GitHub Actions transfer model.

These functions do not implement the full expression language. Unknown input
returns False so a caller can classify it UNKNOWN rather than 'confirmed'.
"""
import re


def official_action(uses, kind):
    """Only an exact named official v4 action satisfies this proof."""
    return str(uses).strip() == 'actions/' + kind + '@v4'


def exact_github_expression(value, target):
    """No substring, concatenation, or expression operators permitted."""
    pattern = r'\$\{\{\s*' + re.escape(target) + r'\s*\}\}'
    return re.fullmatch(pattern, str(value).strip()) is not None


def exact_token(value):
    return any(exact_github_expression(value, target)
               for target in ('github.token', 'secrets.GITHUB_TOKEN'))
