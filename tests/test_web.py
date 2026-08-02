from __future__ import annotations

import asyncio
import http.client
import json
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from mercury.models import (
    Confidence, Conclusion, Direction, Disposition, EffectiveConfig, EvidenceKind,
    Health, Observation, Progress, TaskResult, TaskState,
)
from mercury.history import HistoryRecord
from mercury.web import CSRF_HEADER, MercuryWebServer, WebConfig, WebError


def result(*, state: TaskState = TaskState.COMPLETED) -> TaskResult:
    now = datetime(2026, 8, 2, tzinfo=timezone.utc)
    observation = Observation(
        "web-observation", "web-facade", Disposition.POSITIVE, EvidenceKind.LOCAL_FACT,
        Direction.LOCAL, "127.0.0.1", now, now, 0,
    )
    return TaskResult(
        "web-task", "web", Direction.LOCAL, "127.0.0.1", state, now, now, {},
        EffectiveConfig("web-test", ("127.0.0.1",), False, "test", {}),
        Progress(1, 1, 1), observations=(observation,), conclusions=(Conclusion(
            "web-health", "Web facade result", "Controlled facade test.", Health.HEALTHY,
            Confidence.HIGH, (observation.id,),
        ),),
    )


class FakeApplication:
    calls: list[str] = []

    def __init__(self, *, history) -> None:
        self.history = history

    async def status(self) -> TaskResult:
        type(self).calls.append("status")
        return result()

    async def diagnose(self, request) -> TaskResult:
        type(self).calls.append("diagnose")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return result(state=TaskState.CANCELLED)

    async def discover_passive(self) -> TaskResult:
        type(self).calls.append("discover_passive")
        return result()

    async def discover(self, request) -> TaskResult:
        type(self).calls.append("discover")
        return result()

    async def trace(self, request) -> TaskResult:
        type(self).calls.append("trace")
        return result()

    async def run_paired(self, request) -> TaskResult:
        type(self).calls.append("paired")
        return result()

    async def map_internal(self, request) -> TaskResult:
        type(self).calls.append("mapping")
        return result()

    async def run_coverage(self, request) -> TaskResult:
        type(self).calls.append("coverage")
        return result()

    def history_list(self, *, limit: int):
        type(self).calls.append("history_list")
        return ()

    def compare_history(self, left_task_id: str, right_task_id: str):
        type(self).calls.append("compare_history")
        return {"left_task_id": left_task_id, "right_task_id": right_task_id, "target": "203.0.113.1"}

    def report_history(self, task_id: str):
        type(self).calls.append("report_history")
        return {"task_id": task_id, "result": {"target": "[redacted identifier]"}}

    def history_show(self, task_id: str):
        type(self).calls.append("history_show")
        now = datetime(2026, 8, 2, tzinfo=timezone.utc)
        return HistoryRecord(task_id, "web", TaskState.COMPLETED, now, now, {}, {}, result())


class WebServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        FakeApplication.calls = []
        self.server = MercuryWebServer(
            WebConfig(port=0), history_path=Path(self.temporary.name) / "history.sqlite3",
            app_factory=FakeApplication,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.cookie = ""
        self.csrf = ""

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method: str, path: str, *, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        raw = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        return status, response_headers, raw

    def session(self) -> None:
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        status, _, raw = self.request("GET", "/api/bootstrap", headers={"Cookie": self.cookie})
        self.assertEqual(status, 200)
        self.csrf = json.loads(raw)["csrf"]

    def task_headers(self) -> dict[str, str]:
        return {"Cookie": self.cookie, "Origin": self.origin, "Content-Type": "application/json", CSRF_HEADER: self.csrf}

    def submit(self, payload: dict[str, object]) -> str:
        status, _, raw = self.request("POST", "/api/tasks", body=json.dumps(payload).encode(), headers=self.task_headers())
        self.assertEqual(status, 202)
        return json.loads(raw)["task_id"]

    def poll(self, task_id: str) -> dict[str, object]:
        for _ in range(30):
            status, _, raw = self.request("GET", f"/api/tasks/{task_id}", headers={"Cookie": self.cookie})
            self.assertEqual(status, 200)
            payload = json.loads(raw)
            if payload["state"] not in {"accepted", "running"}:
                return payload
            time.sleep(0.02)
        self.fail("web task did not finish")

    def test_dashboard_session_csrf_and_static_resources(self) -> None:
        self.session()
        status, headers, raw = self.request("GET", "/static/app.js")
        self.assertEqual((status, headers["content-type"]), (200, "text/javascript; charset=utf-8"))
        self.assertIn(b"fetch(", raw)
        status, _, raw = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(raw)["error"]["category"], "web")

    def test_security_boundary_rejects_bad_host_origin_and_csrf(self) -> None:
        self.session()
        status, _, _ = self.request("GET", "/", headers={"Host": "attacker.invalid"})
        self.assertEqual(status, 400)
        raw = json.dumps({"kind": "status"}).encode()
        headers = self.task_headers()
        headers.pop(CSRF_HEADER)
        status, _, _ = self.request("POST", "/api/tasks", body=raw, headers=headers)
        self.assertEqual(status, 403)
        headers = self.task_headers()
        headers["Origin"] = "https://attacker.invalid"
        status, _, _ = self.request("POST", "/api/tasks", body=raw, headers=headers)
        self.assertEqual(status, 403)

    def test_request_parser_rejects_invalid_content_and_shapes(self) -> None:
        self.session()
        headers = self.task_headers()
        headers["Content-Type"] = "text/plain"
        status, _, _ = self.request("POST", "/api/tasks", body=b"x", headers=headers)
        self.assertEqual(status, 415)
        status, _, _ = self.request("POST", "/api/tasks", body=b"{", headers=self.task_headers())
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/tasks", body=b"x" * (16 * 1024 + 1), headers=self.task_headers())
        self.assertEqual(status, 413)
        status, _, raw = self.request("POST", "/api/tasks", body=json.dumps({"kind": "diagnose", "authorized": "false"}).encode(), headers=self.task_headers())
        self.assertEqual(status, 400)
        self.assertIn("authorization", json.loads(raw)["error"]["message"])

    def test_task_dispatch_and_cancellation_use_the_application_facade(self) -> None:
        self.session()
        status_task = self.submit({"kind": "status"})
        finished = self.poll(status_task)
        self.assertEqual(finished["state"], "completed")
        self.assertEqual(finished["result"]["task_id"], "web-task")
        diagnosis = self.submit({"kind": "diagnose", "authorized": True, "targets": ["127.0.0.1:443"]})
        status, _, _ = self.request("DELETE", f"/api/tasks/{diagnosis}", headers={"Cookie": self.cookie, "Origin": self.origin, CSRF_HEADER: self.csrf})
        self.assertEqual(status, 202)
        self.assertEqual(self.poll(diagnosis)["state"], "cancelled")
        self.assertEqual(FakeApplication.calls, ["status", "diagnose"])

    def test_mapping_and_coverage_are_closed_facade_requests(self) -> None:
        self.session()
        mapping = self.submit({
            "kind": "mapping", "cidrs": ["127.0.0.1/32"], "profiles": ["nmap_udp"],
            "ports": [53], "rate": 2, "concurrency": 1, "duration_s": 0, "authorized": True,
        })
        self.assertEqual(self.poll(mapping)["state"], "completed")
        coverage = self.submit({
            "kind": "coverage", "config_path": "peer.json", "identity": "peer", "address": "127.0.0.1",
            "profiles": ["tcp_tagged"], "authorized": True,
        })
        self.assertEqual(self.poll(coverage)["state"], "completed")
        self.assertEqual(FakeApplication.calls, ["mapping", "coverage"])
        status, _, raw = self.request("POST", "/api/tasks", body=json.dumps({
            "kind": "mapping", "cidrs": ["127.0.0.1/32"], "profiles": ["nmap_udp"], "ports": [53],
            "authorized": True, "nmap_args": "--script=default",
        }).encode(), headers=self.task_headers())
        self.assertEqual(status, 400)
        self.assertIn("shape", json.loads(raw)["error"]["message"])

    def test_non_loopback_requires_tls_and_token_before_listener(self) -> None:
        with self.assertRaisesRegex(WebError, "TLS and a token"):
            WebConfig(bind_host="10.20.30.10")

    def test_public_bind_is_rejected_before_listener_configuration(self) -> None:
        with self.assertRaisesRegex(WebError, "private"):
            WebConfig(bind_host="203.0.113.10", certificate_path=Path("cert.pem"), key_path=Path("key.pem"), token="test-token")

    def test_static_dashboard_has_accessible_external_assets(self) -> None:
        html = (Path(__file__).parents[1] / "src" / "mercury" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("<main>", html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('for="kind"', html)
        self.assertIn('src="/static/app.js" defer', html)
        self.assertIn('value="mapping"', html)
        self.assertIn('value="coverage"', html)
        self.assertIn('id="coverage-result"', html)
        self.assertIn('id="candidate-carriers"', html)
        script = (Path(__file__).parents[1] / "src" / "mercury" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("function renderCoverage", script)
        self.assertIn("coverage gap", script)
        self.assertNotIn("onclick=", html)

    def test_history_routes_use_the_broker_facade_and_redact_by_default(self) -> None:
        self.session()
        status, _, raw = self.request("GET", "/api/history", headers={"Cookie": self.cookie})
        self.assertEqual((status, json.loads(raw)), (200, {"tasks": []}))
        status, _, raw = self.request("GET", "/api/history/compare?left=one&right=two", headers={"Cookie": self.cookie})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["target"], "[redacted identifier]")
        status, _, raw = self.request("GET", "/api/history/one/report", headers={"Cookie": self.cookie})
        self.assertEqual((status, json.loads(raw)["result"]["target"]), (200, "[redacted identifier]"))
        status, headers, raw = self.request("GET", "/api/history/one/report?format=html", headers={"Cookie": self.cookie})
        self.assertEqual((status, headers["content-type"]), (200, "text/html; charset=utf-8"))
        self.assertIn(b"Mercury report", raw)
        self.assertEqual(FakeApplication.calls, ["history_list", "compare_history", "report_history", "history_show"])


if __name__ == "__main__":
    unittest.main()
