from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .base import AdapterError


@dataclass(frozen=True)
class HttpResponse:
    status: int
    payload: dict[str, object]


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: dict[str, object] | None = None,
    ) -> HttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibTransport:
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
        body: dict[str, object] | None = None,
    ) -> HttpResponse:
        parsed_url = urlsplit(url)
        if parsed_url.scheme != "https" or not parsed_url.hostname:
            raise AdapterError("provider API URL must use HTTPS")
        if parsed_url.username is not None or parsed_url.password is not None:
            raise AdapterError("provider API URL must not contain embedded credentials")
        if parsed_url.fragment:
            raise AdapterError("provider API URL must not contain a fragment")
        encoded = None
        request_headers = {"Accept": "application/json", **headers}
        if body is not None:
            encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url, data=encoded, headers=request_headers, method=method
        )
        try:
            # URL scheme and hostname are validated immediately above.
            with self._opener.open(request, timeout=30) as response:  # nosec B310
                raw = response.read(1024 * 1024 + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            # Do not retain response bodies: providers can reflect credentials or URLs.
            raise AdapterError(f"provider HTTP request failed with status {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise AdapterError("provider HTTP request failed") from exc
        if len(raw) > 1024 * 1024:
            raise AdapterError("provider response exceeded the 1 MiB safety limit")
        if not raw:
            payload: dict[str, object] = {}
        else:
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AdapterError("provider returned invalid JSON") from exc
            if not isinstance(parsed, dict):
                raise AdapterError("provider returned a non-object JSON response")
            payload = parsed
        return HttpResponse(status=status, payload=payload)
