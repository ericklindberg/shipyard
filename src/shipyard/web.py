from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .connections import ConnectionError, ConnectionStore
from .identity import runtime_identity
from .ledger import Ledger, LedgerError
from .models import ReleaseRun

_INDEX = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shipyard</title>
<style>
:root{color-scheme:dark;--bg:#0a0d12;--line:#253043;--muted:#91a0b5;--ok:#54d38a;--warn:#f1c75b;--bad:#ff7272}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#eef3fa;font:15px ui-monospace,SFMono-Regular,Menlo,monospace}
main{max-width:1120px;margin:auto;padding:44px 24px}header{display:flex;align-items:end;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:18px}
h1{margin:0;font-size:30px;letter-spacing:-1px}p{color:var(--muted)}table{width:100%;border-collapse:collapse;margin-top:28px}th,td{text-align:left;padding:14px 10px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:500}a{color:#8bc4ff;text-decoration:none}.succeeded{color:var(--ok)}.uncertain,.awaiting_authorization{color:var(--warn)}.failed{color:var(--bad)}code{font-size:13px}.empty{padding:60px 0;text-align:center}</style>
</head><body><main><header><div><h1>SHIPYARD</h1><p>Candidate-bound deployment control</p></div><code id="health">connecting</code></header><section id="content"></section></main>
<script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load(){const [h,r,p]=await Promise.all([fetch('/api/health').then(x=>x.json()),fetch('/api/runs').then(x=>x.json()),fetch('/api/connections').then(x=>x.json())]);
document.querySelector('#health').textContent=`${h.version.package_version} · ${p.connections.length} connections · ${r.runs.length} runs`;
const c=document.querySelector('#content'),blocks=[];
if(p.connections.length)blocks.push(`<h2>Connections</h2><table><thead><tr><th>Name</th><th>Provider</th><th>Action</th><th>Destination</th><th>Credentials ready</th></tr></thead><tbody>${p.connections.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.provider)}</td><td><code>${esc(x.action)}</code></td><td>${esc(x.destination)}</td><td>${x.credential_env.every(e=>!e.required||e.present)?'yes':'check required'}</td></tr>`).join('')}</tbody></table>`);
if(r.runs.length)blocks.push(`<h2>Runs</h2><table><thead><tr><th>Run</th><th>Status</th><th>Provider</th><th>Destination</th><th>Source</th><th>Updated</th></tr></thead><tbody>${r.runs.map(x=>`<tr><td><a href="/api/runs/${encodeURIComponent(x.run_id)}">${esc(x.run_id)}</a></td><td class="${esc(x.status)}">${esc(x.status)}</td><td>${esc(x.provider)}</td><td>${esc(x.destination)}</td><td><code>${esc(x.source_sha?.slice(0,12))}</code></td><td>${esc(x.updated_at)}</td></tr>`).join('')}</tbody></table>`);
c.innerHTML=blocks.length?blocks.join(''):'<p class="empty">No connections or runs yet. Start with <code>shipyard connection add …</code></p>'}
load().catch(e=>document.querySelector('#content').innerHTML=`<p class="empty">${esc(e)}</p>`);
</script></body></html>"""


def _summary(run: ReleaseRun) -> dict[str, object]:
    return {
        "run_id": run.run_id,
        "status": run.status,
        "provider": run.provider,
        "destination": run.destination,
        "source_sha": run.source.sha,
        "candidate_digest": run.candidate_digest,
        "created_at": run.created_at,
        "updated_at": run.updated_at,
    }


def _detail(ledger: Ledger, run: ReleaseRun) -> dict[str, object]:
    return {
        **_summary(run),
        "source": {
            "path": str(run.source.path),
            "sha": run.source.sha,
            "branch": run.source.branch,
            "dirty": run.source.dirty,
            "remote_url": run.source.remote_url,
        },
        "approval": ledger.get_approval(run.run_id),
        "audit_chain_valid": ledger.verify_audit_chain(run.run_id),
        "audit_events": ledger.list_audit_events(run.run_id),
        "steps": [
            {
                "id": step.id,
                "name": step.name,
                "effect": step.effect,
                "action": step.action,
                "status": step.status,
                "attempts": step.attempts,
                "operation_id": step.operation_id,
                "provider_status": step.provider_status,
                "readback": step.readback,
                "output_sha256": step.output_sha256,
                "output_preview": step.output_preview,
            }
            for step in run.steps
        ],
    }


def _allowed_host_header(value: str | None) -> bool:
    if not value:
        return False
    try:
        hostname = urlparse(f"//{value}").hostname
    except ValueError:
        return False
    return hostname is not None and hostname.lower() in {"127.0.0.1", "::1", "localhost"}


def create_server(
    state_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    config_dir: str | Path | None = None,
):
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("Shipyard's read-only web app may only bind to loopback")
    ledger = Ledger(state_dir)
    connections = ConnectionStore(config_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "Shipyard"

        def _headers(self, status: HTTPStatus, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()

        def _json(self, payload: dict[str, object], status=HTTPStatus.OK) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8")
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if not _allowed_host_header(self.headers.get("Host")):
                self._json({"error": "forbidden host"}, HTTPStatus.FORBIDDEN)
                return
            route = urlparse(self.path).path
            try:
                if route == "/":
                    self._headers(HTTPStatus.OK, "text/html; charset=utf-8")
                    self.wfile.write(_INDEX.encode("utf-8"))
                    return
                if route == "/api/health":
                    self._json({"status": "ok", "version": runtime_identity()})
                    return
                if route == "/api/runs":
                    self._json({"runs": [_summary(run) for run in ledger.list_runs()]})
                    return
                if route == "/api/connections":
                    self._json(
                        {
                            "connections": [
                                profile.public_payload() for profile in connections.list()
                            ]
                        }
                    )
                    return
                prefix = "/api/runs/"
                if route.startswith(prefix) and "/" not in route[len(prefix) :]:
                    run = ledger.get_run(route[len(prefix) :])
                    self._json(_detail(ledger, run))
                    return
            except (ConnectionError, LedgerError) as exc:
                self._json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
                return
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)
