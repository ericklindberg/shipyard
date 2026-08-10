from __future__ import annotations

import pytest

from shipyard.adapters.base import AdapterError
from shipyard.adapters.http import UrllibTransport


class FailIfOpened:
    def open(self, *_args, **_kwargs):
        raise AssertionError("network opener must not be reached")


class OversizedResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return b"x" * (1024 * 1024 + 1)


class OversizedOpener:
    def open(self, *_args, **_kwargs):
        return OversizedResponse()


def test_http_transport_rejects_oversized_responses() -> None:
    transport = UrllibTransport()
    transport._opener = OversizedOpener()  # type: ignore[assignment]

    with pytest.raises(AdapterError, match="1 MiB safety limit"):
        transport.request("GET", "https://example.invalid/v1/resource", headers={})


def test_http_transport_rejects_credential_urls_before_network() -> None:
    transport = UrllibTransport()
    transport._opener = FailIfOpened()  # type: ignore[assignment]

    with pytest.raises(AdapterError, match="embedded credentials"):
        transport.request(
            "GET",
            "https://user:" + "secret@example.invalid/v1/resource",
            headers={},
        )
    with pytest.raises(AdapterError, match="fragment"):
        transport.request(
            "GET",
            "https://example.invalid/v1/resource#secret",
            headers={},
        )


def test_http_transport_installs_no_redirect_and_no_proxy_policies(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:8080")
    transport = UrllibTransport()
    handler = next(
        item
        for item in transport._opener.handlers
        if type(item).__name__ == "_NoRedirectHandler"
    )
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://other.invalid") is None
    assert not any(
        type(item).__name__ == "ProxyHandler" for item in transport._opener.handlers
    )
