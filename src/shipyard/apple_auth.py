from __future__ import annotations

import base64
import json
import os
import re
import stat
import time
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .adapters.base import AdapterError
from .safe_files import SafeFileError, open_relative_regular

_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_KEY_ID = re.compile(r"^[A-Za-z0-9]{6,64}$")
_ISSUER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{5,127}$")
_MAX_KEY_BYTES = 64 * 1024
APPLE_AUTH_OPTION_KEYS = frozenset(
    {"token_env", "issuer_id_env", "key_id_env", "private_key_path_env"}
)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _required_env_name(config: Mapping[str, object], key: str) -> str:
    value = config.get(key)
    if (
        not isinstance(value, str)
        or _ENV_NAME.fullmatch(value) is None
        or not value.startswith("APPLE_")
    ):
        raise AdapterError(f"Apple credential reference {key} must use an APPLE_ variable")
    return value


def _required_env_value(name: str) -> str:
    value = os.environ.get(name)
    if not value or any(character in value for character in ("\x00", "\r", "\n")):
        raise AdapterError(f"credential environment variable {name} is not set or malformed")
    return value


def _read_private_key(config: Mapping[str, object]) -> ec.EllipticCurvePrivateKey:
    path_env = _required_env_name(config, "private_key_path_env")
    configured = _required_env_value(path_env)
    path = Path(configured).expanduser()
    if not path.is_absolute():
        raise AdapterError("Apple private key path must be absolute")
    try:
        relative = path.relative_to(Path("/")).as_posix()
        descriptor = open_relative_regular(Path("/"), relative)
    except (SafeFileError, ValueError) as exc:
        raise AdapterError("Apple private key cannot be opened without following symlinks") from exc
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
            or mode not in {0o400, 0o600}
        ):
            raise AdapterError("Apple private key must be user-owned and mode 0400 or 0600")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_KEY_BYTES:
            raise AdapterError("Apple private key size is invalid")
        content = bytearray()
        while chunk := os.read(descriptor, min(8192, _MAX_KEY_BYTES + 1 - len(content))):
            content.extend(chunk)
            if len(content) > _MAX_KEY_BYTES:
                raise AdapterError("Apple private key size is invalid")
    finally:
        os.close(descriptor)
    try:
        loaded = serialization.load_pem_private_key(bytes(content), password=None)
    except (TypeError, ValueError) as exc:
        raise AdapterError("Apple private key is not a valid unencrypted PEM key") from exc
    finally:
        content[:] = b"\x00" * len(content)
    if not isinstance(loaded, ec.EllipticCurvePrivateKey) or not isinstance(
        loaded.curve, ec.SECP256R1
    ):
        raise AdapterError("Apple private key must be an ES256 P-256 key")
    return loaded


def _native_token(config: Mapping[str, object], *, now: int | None = None) -> str:
    issuer_env = _required_env_name(config, "issuer_id_env")
    key_id_env = _required_env_name(config, "key_id_env")
    issuer = _required_env_value(issuer_env)
    key_id = _required_env_value(key_id_env)
    if _ISSUER_ID.fullmatch(issuer) is None:
        raise AdapterError("Apple issuer ID is invalid")
    if _KEY_ID.fullmatch(key_id) is None:
        raise AdapterError("Apple key ID is invalid")
    issued_at = int(time.time()) if now is None else now
    header = {"alg": "ES256", "kid": key_id, "typ": "JWT"}
    payload = {
        "iss": issuer,
        "iat": issued_at,
        "exp": issued_at + 600,
        "aud": "appstoreconnect-v1",
    }
    signing_input = (
        _base64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        + "."
        + _base64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    )
    private_key = _read_private_key(config)
    der_signature = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return signing_input + "." + _base64url(signature)


def validate_apple_credential_references(
    config: Mapping[str, object],
) -> tuple[str, ...]:
    token_env = config.get("token_env")
    native_keys = ("issuer_id_env", "key_id_env", "private_key_path_env")
    native_present = [key for key in native_keys if config.get(key) is not None]
    if token_env is not None and native_present:
        raise AdapterError(
            "Apple credentials must use either token_env or issuer/key/private-key references"
        )
    selected = ("token_env",) if token_env is not None else native_keys
    if token_env is None and len(native_present) != len(native_keys):
        raise AdapterError(
            "Apple native credentials require issuer_id_env, key_id_env, and private_key_path_env"
        )
    return tuple(_required_env_name(config, key) for key in selected)


def apple_bearer_token(config: Mapping[str, object]) -> str:
    selected = validate_apple_credential_references(config)
    if selected == (str(config.get("token_env")),):
        return _required_env_value(selected[0])
    return _native_token(config)


def apple_headers(config: Mapping[str, object]) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {apple_bearer_token(config)}",
        "Accept": "application/json",
    }
