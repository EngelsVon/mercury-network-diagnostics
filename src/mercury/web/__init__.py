"""Small secure stdlib WebUI adapter for the shared Mercury facade."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import math
import secrets
import socket
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from ..app import MercuryApplication
from ..codec import dumps_document, result_to_wire
from ..discovery import DiscoveryRequest
from ..history import HistoryStore, sanitize_exception
from ..models import TaskResult
from ..paired import PairedRequest
from ..profiles import DiagnosisRequest
from ..trace import TraceRequest
from ..reports import redact


MAX_BODY_BYTES = 16 * 1024
MAX_STATIC_BYTES = 512 * 1024
SESSION_COOKIE = "mercury_session"
CSRF_HEADER = "X-Mercury-CSRF"
STATIC_DIR = Path(__file__).with_name("static")


class WebError(ValueError):
    """HTTP input/configuration is invalid without leaking internals."""


@dataclass(frozen=True, slots=True)
class WebConfig:
    bind_host: str = "127.0.0.1"
    port: int = 8765
    certificate_path: Path | None = None
    key_path: Path | None = None
    token: str | None = None

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.bind_host)
        except ValueError as exc:
            raise WebError("web bind host must be a numeric IP address") from exc
        if type(self.port) is not int or not 0 <= self.port <= 65_535:
            raise WebError("web port must be within 0..65535")
        if (self.certificate_path is None) != (self.key_path is None):
            raise WebError("web TLS requires both certificate and key paths")
        non_loopback = not address.is_loopback
        if non_loopback and (self.certificate_path is None or not self.token):
            raise WebError("non-loopback WebUI requires TLS and a token")
        if self.token is not None and (not isinstance(self.token, str) or not self.token or len(self.token) > 512):
            raise WebError("web token is invalid")
        object.__setattr__(self, "bind_host", address.compressed)

    @property
    def loopback(self) -> bool:
        return ipaddress.ip_address(self.bind_host).is_loopback

    @property
    def tls_enabled(self) -> bool:
        return self.certificate_path is not None


@dataclass(slots=True)
class _WebTask:
    task_id: str
    state: str = "accepted"
    result: TaskResult | None = None
    error: str | None = None
    task: asyncio.Task[None] | None = None


class WebTaskBroker:
    """One event loop for facade coroutines; SQLite is opened per operation."""

    def __init__(self, history_path: str | Path | None, app_factory: Callable[..., MercuryApplication] = MercuryApplication) -> None:
        self.history_path = history_path
        self.app_factory = app_factory
        self._loop = asyncio.new_event_loop()
        self._tasks: dict[str, _WebTask] = {}
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="mercury-web-tasks", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()
        pending = asyncio.all_tasks(self._loop)
        for task in pending:
            task.cancel()
        self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self._loop.close()

    def submit(self, payload: Mapping[str, object]) -> str:
        normalized = _normalize_payload(payload)
        identifier = secrets.token_urlsafe(18)
        record = _WebTask(identifier)
        with self._lock:
            self._tasks[identifier] = record
        ready = threading.Event()

        def schedule() -> None:
            record.task = self._loop.create_task(self._execute(record, normalized), name=f"mercury:web:{identifier}")
            ready.set()
        self._loop.call_soon_threadsafe(schedule)
        ready.wait(timeout=2)
        if record.task is None:
            raise WebError("web task scheduler is unavailable")
        return identifier

    async def _execute(self, record: _WebTask, payload: dict[str, object]) -> None:
        record.state = "running"
        try:
            with HistoryStore(self.history_path) as history:
                application = self.app_factory(history=history)
                result = await _dispatch_facade(application, payload)
            with self._lock:
                record.result = result
                record.state = result.state.value
        except asyncio.CancelledError:
            with self._lock:
                record.state = "cancelled"
        except Exception as exc:
            with self._lock:
                record.error = sanitize_exception(exc)
                record.state = "failed"

    def snapshot(self, identifier: str) -> dict[str, object] | None:
        with self._lock:
            record = self._tasks.get(identifier)
            if record is None:
                return None
            payload: dict[str, object] = {"task_id": identifier, "state": record.state}
            if record.result is not None:
                payload["result"] = result_to_wire(record.result)
                payload["progress"] = result_to_wire(record.result)["progress"]
            if record.error is not None:
                payload["error"] = {"category": "task", "message": record.error}
            return payload

    def cancel(self, identifier: str) -> bool:
        with self._lock:
            record = self._tasks.get(identifier)
            if record is None or record.task is None or record.task.done():
                return False
            self._loop.call_soon_threadsafe(record.task.cancel)
            return True

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=3)

    def query(self, operation: Callable[[MercuryApplication], dict[str, object]]) -> dict[str, object]:
        """Run a read-only facade operation on the broker-owned SQLite thread."""
        ready = threading.Event()
        outcome: dict[str, object] = {}

        async def execute() -> None:
            try:
                with HistoryStore(self.history_path) as history:
                    outcome["value"] = operation(self.app_factory(history=history))
            except Exception as exc:
                outcome["error"] = exc
            finally:
                ready.set()

        self._loop.call_soon_threadsafe(lambda: self._loop.create_task(execute()))
        if not ready.wait(timeout=2):
            raise WebError("history service is unavailable")
        if "error" in outcome:
            raise WebError(sanitize_exception(outcome["error"]))
        value = outcome.get("value")
        if not isinstance(value, dict):
            raise WebError("history service returned an invalid response")
        return value


def _require_shape(value: object, *, keys: frozenset[str], required: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - keys or not required.issubset(value):
        raise WebError("request JSON shape is not allowed")
    return dict(value)


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise WebError(f"{name} is invalid")
    return value


def _finite_number(value: object, name: str, default: float) -> float:
    if value is None:
        return default
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        raise WebError(f"{name} is invalid")
    return float(value)


def _bounded_int(value: object, name: str, default: int) -> int:
    if value is None:
        return default
    if type(value) is not int:
        raise WebError(f"{name} is invalid")
    return value


def _authorized(value: object) -> bool:
    if type(value) is not bool:
        raise WebError("authorization attestation is invalid")
    return value


def _normalize_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Validate the closed Web request contract before background execution."""
    if not isinstance(payload, dict):
        raise WebError("request JSON shape is not allowed")
    kind = payload.get("kind")
    if kind == "status" or kind == "discover_passive":
        return _require_shape(payload, keys=frozenset({"kind"}), required=frozenset({"kind"}))
    if kind == "diagnose":
        body = _require_shape(payload, keys=frozenset({"kind", "profile", "targets", "timeout_s", "authorized"}), required=frozenset({"kind", "authorized"}))
        targets = body.get("targets", [])
        if not isinstance(targets, list) or len(targets) > 16:
            raise WebError("diagnosis targets are invalid")
        body["targets"] = [_string(item, "diagnosis target") for item in targets]
        profile = body.get("profile", "basic")
        if profile not in ("basic", "china"):
            raise WebError("diagnosis profile is invalid")
        body["profile"] = profile
        body["timeout_s"] = _finite_number(body.get("timeout_s"), "diagnosis timeout", 3.0)
        body["authorized"] = _authorized(body["authorized"])
        return body
    if kind == "discover":
        body = _require_shape(payload, keys=frozenset({"kind", "network", "scope", "profile", "ports", "timeout_s", "authorized", "confirmations"}), required=frozenset({"kind", "network", "scope", "authorized"}))
        body["network"] = _string(body["network"], "discovery network")
        body["scope"] = _string(body["scope"], "discovery scope")
        profile = body.get("profile", "common")
        if profile not in ("common", "custom", "full"):
            raise WebError("discovery profile is invalid")
        body["profile"] = profile
        ports = body.get("ports", [])
        confirmations = body.get("confirmations", [])
        if not isinstance(ports, list) or not all(type(item) is int and 1 <= item <= 65_535 for item in ports) or not isinstance(confirmations, list) or not all(isinstance(item, str) and len(item) <= 256 for item in confirmations):
            raise WebError("discovery ports or confirmations are invalid")
        body["ports"] = ports
        body["confirmations"] = confirmations
        body["timeout_s"] = _finite_number(body.get("timeout_s"), "discovery timeout", 1.0)
        body["authorized"] = _authorized(body["authorized"])
        return body
    if kind == "trace":
        body = _require_shape(payload, keys=frozenset({"kind", "target", "scope", "max_hops", "repeats", "timeout_s", "authorized"}), required=frozenset({"kind", "target", "scope", "authorized"}))
        body["target"] = _string(body["target"], "trace target")
        body["scope"] = _string(body["scope"], "trace scope")
        body["max_hops"] = _bounded_int(body.get("max_hops"), "trace hop limit", 8)
        body["repeats"] = _bounded_int(body.get("repeats"), "trace repeat count", 3)
        body["timeout_s"] = _finite_number(body.get("timeout_s"), "trace timeout", 1.0)
        body["authorized"] = _authorized(body["authorized"])
        return body
    if kind == "paired":
        body = _require_shape(payload, keys=frozenset({"kind", "config_path", "identity", "address", "timeout_s", "authorized"}), required=frozenset({"kind", "config_path", "identity", "address", "authorized"}))
        for field in ("config_path", "identity", "address"):
            body[field] = _string(body[field], field)
        body["timeout_s"] = _finite_number(body.get("timeout_s"), "paired timeout", 3.0)
        body["authorized"] = _authorized(body["authorized"])
        return body
    raise WebError("task kind is not allowed")


async def _dispatch_facade(application: MercuryApplication, payload: Mapping[str, object]) -> TaskResult:
    kind = payload.get("kind")
    if kind == "status":
        return await application.status()
    if kind == "diagnose":
        targets = payload.get("targets", [])
        assert isinstance(targets, list)
        return await application.diagnose(DiagnosisRequest(profile="custom" if targets else payload["profile"], targets=tuple(targets), timeout_s=payload["timeout_s"], authorized=payload["authorized"]))
    if kind == "discover_passive":
        return await application.discover_passive()
    if kind == "discover":
        return await application.discover(DiscoveryRequest(network=payload["network"], scope=payload["scope"], profile=payload["profile"], ports=tuple(payload["ports"]), timeout_s=payload["timeout_s"], authorized=payload["authorized"], confirmations=tuple(payload["confirmations"])))
    if kind == "trace":
        return await application.trace(TraceRequest(target=payload["target"], scope=payload["scope"], max_hops=payload["max_hops"], repeats=payload["repeats"], timeout_s=payload["timeout_s"], authorized=payload["authorized"]))
    if kind == "paired":
        return await application.run_paired(PairedRequest(identity=payload["identity"], address=payload["address"], config_path=payload["config_path"], timeout_s=payload["timeout_s"], authorized=payload["authorized"]))
    raise RuntimeError("normalized task kind is not allowed")


class MercuryWebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: WebConfig, *, history_path: str | Path | None = None, app_factory: Callable[..., MercuryApplication] = MercuryApplication) -> None:
        self.config = config
        self.address_family = socket.AF_INET6 if ":" in config.bind_host else socket.AF_INET
        self.broker = WebTaskBroker(history_path, app_factory=app_factory)
        self.sessions: dict[str, str] = {}
        self.session_lock = threading.Lock()
        super().__init__((config.bind_host, config.port), MercuryRequestHandler)
        if config.tls_enabled:
            assert config.certificate_path is not None and config.key_path is not None
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(config.certificate_path, config.key_path)
            self.socket = context.wrap_socket(self.socket, server_side=True)

    def server_close(self) -> None:
        self.broker.close()
        super().server_close()

    @property
    def scheme(self) -> str:
        return "https" if self.config.tls_enabled else "http"


class MercuryRequestHandler(BaseHTTPRequestHandler):
    server: MercuryWebServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        if not host or any(character.isspace() for character in host):
            return False
        hostname = host
        if host.startswith("["):
            hostname = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:
            hostname = host.rsplit(":", 1)[0]
        allowed = {self.server.config.bind_host}
        if self.server.config.loopback:
            allowed.update({"127.0.0.1", "::1", "localhost"})
        return hostname.casefold() in {item.casefold() for item in allowed}

    def _token_ok(self) -> bool:
        if self.server.config.loopback:
            return True
        expected = self.server.config.token
        supplied = self.headers.get("Authorization", "")
        return expected is not None and hmac.compare_digest(supplied, f"Bearer {expected}")

    def _session(self) -> tuple[str, str] | None:
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            value = cookie.get(SESSION_COOKIE)
            session = value.value if value is not None else None
        except Exception:
            return None
        with self.server.session_lock:
            csrf = self.server.sessions.get(session or "")
            return (session, csrf) if session is not None and csrf is not None else None

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        return origin == f"{self.server.scheme}://{self.headers.get('Host')}"

    def _csrf_ok(self) -> bool:
        session = self._session()
        return session is not None and hmac.compare_digest(self.headers.get(CSRF_HEADER, ""), session[1])

    def _security_headers(self) -> None:
        self.send_header("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, status: HTTPStatus, value: Mapping[str, object]) -> None:
        raw = dumps_document(value).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json(status, {"error": {"category": "web", "message": message}})

    def _guard(self, *, mutation: bool = False, session: bool = False) -> bool:
        if not self._host_ok():
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid Host header")
            return False
        if not self._token_ok():
            self._send_error(HTTPStatus.UNAUTHORIZED, "token is required")
            return False
        if session and self._session() is None:
            self._send_error(HTTPStatus.UNAUTHORIZED, "a dashboard session is required")
            return False
        if mutation and (not self._origin_ok() or not self._csrf_ok()):
            self._send_error(HTTPStatus.FORBIDDEN, "same-origin session and CSRF header are required")
            return False
        return True

    def _read_json(self) -> dict[str, object] | None:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold() != "application/json":
            self._send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "application/json is required")
            return None
        length_text = self.headers.get("Content-Length")
        if length_text is None or not length_text.isdecimal():
            self._send_error(HTTPStatus.LENGTH_REQUIRED, "bounded Content-Length is required")
            return None
        length = int(length_text)
        if length > MAX_BODY_BYTES:
            self._send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body exceeds limit")
            return None
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_error(HTTPStatus.BAD_REQUEST, "malformed JSON")
            return None
        if not isinstance(value, dict):
            self._send_error(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
            return None
        return value

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            if not self._guard():
                return
            session = secrets.token_urlsafe(24)
            csrf = secrets.token_urlsafe(24)
            with self.server.session_lock:
                if len(self.server.sessions) >= 256:
                    self.server.sessions.clear()
                self.server.sessions[session] = csrf
            raw = self._static_bytes("index.html")
            if raw is None:
                return
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/" + ("; Secure" if self.server.config.tls_enabled else ""))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if not self._guard(session=path.startswith("/api/")):
            return
        if path == "/api/bootstrap":
            session = self._session()
            assert session is not None
            self._send_json(HTTPStatus.OK, {"csrf": session[1], "loopback": self.server.config.loopback})
            return
        if path == "/api/history":
            self._send_json(HTTPStatus.OK, self.server.broker.query(lambda app: {"tasks": [
                {"task_id": item.task_id, "task_kind": item.task_kind, "state": item.state.value, "updated_at": item.updated_at.isoformat()}
                for item in app.history_list(limit=50)
            ]}))
            return
        if path == "/api/history/compare":
            query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            left, right = query.get("left"), query.get("right")
            if left is None or right is None or len(left) != 1 or len(right) != 1:
                self._send_error(HTTPStatus.BAD_REQUEST, "two history task IDs are required")
                return
            try:
                payload = self.server.broker.query(lambda app: redact(app.compare_history(left[0], right[0])))
            except WebError as exc:
                self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self._send_json(HTTPStatus.OK, payload)
            return
        if path.startswith("/api/history/") and path.endswith("/report"):
            identifier = path.removeprefix("/api/history/").removesuffix("/report").rstrip("/")
            try:
                payload = self.server.broker.query(lambda app: app.report_history(identifier))
            except WebError as exc:
                self._send_error(HTTPStatus.NOT_FOUND, str(exc))
                return
            self._send_json(HTTPStatus.OK, payload)
            return
        if path.startswith("/api/tasks/"):
            snapshot = self.server.broker.snapshot(path.rsplit("/", 1)[-1])
            if snapshot is None:
                self._send_error(HTTPStatus.NOT_FOUND, "task was not found")
            else:
                self._send_json(HTTPStatus.OK, snapshot)
            return
        names = {"/static/app.js": ("app.js", "text/javascript; charset=utf-8"), "/static/style.css": ("style.css", "text/css; charset=utf-8")}
        asset = names.get(path)
        if asset is None:
            self._send_error(HTTPStatus.NOT_FOUND, "route was not found")
            return
        raw = self._static_bytes(asset[0])
        if raw is None:
            return
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", asset[1])
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        if not self._guard(mutation=True, session=True):
            return
        if urlsplit(self.path).path != "/api/tasks":
            self._send_error(HTTPStatus.NOT_FOUND, "route was not found")
            return
        payload = self._read_json()
        if payload is None:
            return
        try:
            identifier = self.server.broker.submit(payload)
        except (WebError, ValueError) as exc:
            self._send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self._send_json(HTTPStatus.ACCEPTED, {"task_id": identifier, "state": "accepted"})

    def do_DELETE(self) -> None:
        if not self._guard(mutation=True, session=True):
            return
        path = urlsplit(self.path).path
        if not path.startswith("/api/tasks/"):
            self._send_error(HTTPStatus.NOT_FOUND, "route was not found")
            return
        if self.server.broker.cancel(path.rsplit("/", 1)[-1]):
            self._send_json(HTTPStatus.ACCEPTED, {"state": "cancelling"})
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "active task was not found")

    def _static_bytes(self, name: str) -> bytes | None:
        try:
            raw = (STATIC_DIR / name).read_bytes()
        except OSError:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "static asset is unavailable")
            return None
        if len(raw) > MAX_STATIC_BYTES:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "static asset exceeds limit")
            return None
        return raw


def serve_web(config: WebConfig, *, history_path: str | Path | None = None, app_factory: Callable[..., MercuryApplication] = MercuryApplication) -> None:
    server = MercuryWebServer(config, history_path=history_path, app_factory=app_factory)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


__all__ = ["CSRF_HEADER", "MAX_BODY_BYTES", "MercuryWebServer", "SESSION_COOKIE", "WebConfig", "WebError", "WebTaskBroker", "serve_web"]
