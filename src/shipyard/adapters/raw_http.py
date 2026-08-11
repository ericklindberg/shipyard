from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .base import AdapterError

_MAX_BODY_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class RawHttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class RawHttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> RawHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibRawTransport:
    """Bounded HTTPS transport for typed APIs that require non-JSON bodies."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler()
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> RawHttpResponse:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise AdapterError("provider API URL must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise AdapterError("provider API URL must not contain embedded credentials")
        if parsed.fragment:
            raise AdapterError("provider API URL must not contain a fragment")
        if body is not None and len(body) > _MAX_BODY_BYTES:
            raise AdapterError("provider request exceeded the 4 MiB safety limit")
        if content_type is not None and body is None:
            raise AdapterError("provider request content type requires a body")
        request_headers = dict(headers)
        if content_type is not None:
            request_headers["Content-Type"] = content_type
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method=method
        )
        try:
            # URL scheme and hostname are validated immediately above.
            with self._opener.open(request, timeout=30) as response:  # nosec B310
                encoded = response.read(_MAX_BODY_BYTES + 1)
                status = response.status
                response_headers = {
                    name.lower(): value.strip() for name, value in response.headers.items()
                }
        except urllib.error.HTTPError as exc:
            # Provider bodies may reflect credentials; never retain them on errors.
            raise AdapterError(f"provider HTTP request failed with status {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise AdapterError("provider HTTP request failed") from exc
        if len(encoded) > _MAX_BODY_BYTES:
            raise AdapterError("provider response exceeded the 4 MiB safety limit")
        return RawHttpResponse(status, response_headers, encoded)
