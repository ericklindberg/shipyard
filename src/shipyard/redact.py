from __future__ import annotations

import re

_SECRET_NAME = (
    r"access[_-]?token|api[_-]?key|client[_-]?secret|connection[_-]?string|"
    r"credential|id[_-]?token|password|passwd|private[_-]?key|refresh[_-]?token|"
    r"secret|session|signing[_-]?key|token|x-amz-signature|signature|sig"
)
_JSON_SECRET = re.compile(
    rf'''(?i)(["'](?:{_SECRET_NAME})["']\s*:\s*)(["'])(.*?)(\2)'''
)
_CREDENTIAL_HEADER = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|x-api-key|x-auth-token|"
    r"cookie|set-cookie)\s*:\s*).*$"
)
_PATTERNS = (
    re.compile(
        rf"(?i)(\b(?:{_SECRET_NAME})\b\s*[:=]\s*)([^\s,;&]+)"
    ),
    re.compile(r"(?i)(\bBearer\s+)([^\s,;]+)"),
    re.compile(r"(?i)(\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://)([^\s]+)"),
)
_URL_CREDENTIALS = re.compile(r"(?i)(\bhttps?://)[^/@\s]+@")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_OPAQUE_SECRETS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
_SECRET_FLAGS = {
    "--api-key",
    "--apikey",
    "--auth",
    "--aws-sigv4",
    "--oauth2-bearer",
    "--password",
    "--proxy-user",
    "--secret",
    "--token",
    "--user",
    "-u",
}


def redact(text: str) -> str:
    """Remove common credential shapes before output reaches durable storage."""
    result = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    result = _JSON_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]{match.group(4)}",
        result,
    )
    result = _CREDENTIAL_HEADER.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    result = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", result)
    for pattern in _OPAQUE_SECRETS:
        result = pattern.sub("[REDACTED]", result)
    for pattern in _PATTERNS:
        result = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", result)
    return result


def redact_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Redact secrets passed as adjacent or equals-style command arguments."""
    result: list[str] = []
    redact_next = False
    for argument in argv:
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        lowered = argument.lower()
        if lowered in _SECRET_FLAGS:
            result.append(argument)
            redact_next = True
            continue
        matched_flag = next(
            (flag for flag in _SECRET_FLAGS if lowered.startswith(f"{flag}=")), None
        )
        if matched_flag is not None:
            result.append(f"{argument[: len(matched_flag)]}=[REDACTED]")
            continue
        result.append(redact(argument))
    return tuple(result)
