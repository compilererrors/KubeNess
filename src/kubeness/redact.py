"""Masking of likely credentials in text collected from the cluster.

Masking is an extra layer, not a guarantee: the first protection is to collect
only the fields that are needed.
"""

from __future__ import annotations

import re

MASK = "[REDACTED]"

# Names under which a value is a credential, in running text and as a key in a structure.
_KEYWORD = r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)s?"
_SECRET_KEY = re.compile(r"(?i)" + _KEYWORD + r"$")

# (pattern, replacement, hints): a pattern runs only when one of its lower-case hints
# occurs in the text. Most log text has none, which keeps masking cheap.
_PATTERNS: list[tuple[re.Pattern, str, tuple[str, ...]]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), MASK,
     ("private key-----",)),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 " + MASK, ("bearer", "basic")),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK, ("eyj",)),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), MASK, ("akia", "asia")),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b"), MASK,
     ("_", "xox", "sk-")),
    (re.compile(r"(://[^:/\s@]*:)[^@/\s]+@"), r"\1" + MASK + "@", ("://",)),
    (
        re.compile(
            # No prefix group: matching from the keyword (DB_PASSWORD matches at PASSWORD)
            # avoids backtracking over every word in the text.
            r"(?i)(" + _KEYWORD + r")"
            r"([\"']?\s*[:=]\s*[\"']?)([^\s\"',;&]+)"
        ),
        r"\1\2" + MASK,
        ("pass", "pwd", "secret", "token", "key", "credential"),
    ),
]


def redact(text: str) -> tuple[str, int]:
    """Return the masked text and the number of replacements."""
    total = 0
    lower = text.lower()
    for pattern, repl, hints in _PATTERNS:
        if not any(h in lower for h in hints):
            continue
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def redact_obj(obj: object, _under_secret_key: bool = False) -> object:
    """Return a masked copy of a JSON-like structure.

    Every string is masked like text, and every value stored under a credential-like
    key (password, apiKey, DB_TOKEN ...) is masked whole, however deep it sits below
    that key. So is the value of a name/value pair whose name is credential-like, the
    shape of a container env entry. This walks the structure instead of masking its
    JSON text: a pattern that ends inside an escaped quote would leave text that no
    longer parses.
    """
    if isinstance(obj, dict):
        name = obj.get("name")
        pair_secret = isinstance(name, str) and _SECRET_KEY.search(name) is not None and "value" in obj
        return {k: redact_obj(v, _under_secret_key or (isinstance(k, str) and _SECRET_KEY.search(k) is not None)
                              or (pair_secret and k == "value"))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _under_secret_key) for v in obj]
    if _under_secret_key and isinstance(obj, (str, int, float)) and not isinstance(obj, bool) and obj != "":
        return MASK
    if isinstance(obj, str):
        return redact(obj)[0]
    return obj
