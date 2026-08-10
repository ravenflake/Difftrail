import json
import socket
import tempfile
import threading
import unittest
from datetime import timedelta
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from difftrail.db import Database
from difftrail.models import Event, IncidentRequest, utc_now
from difftrail.ui_api import UiServer


class UiHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.database_path = Path(self.folder.name) / "journal.db"
        self.server = UiServer(("127.0.0.1", 0), self.database_path)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.folder.cleanup()

    def request(self, method: str, path: str, body: object | None = None, **headers: str):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            payload = None
        return response.status, payload

    def test_get_routes_and_cors_guard(self) -> None:
        for path in ("/api/bootstrap", "/api/automation", "/api/timeline", "/api/incidents", "/api/health", "/api/doctor"):
            status, payload = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIsNotNone(payload, path)

        status, payload = self.request("GET", "/api/timeline?kind=invalid")
        self.assertEqual(status, 400)
        self.assertIn("kind", payload["error"])

        status, payload = self.request("GET", "/api/timeline?kind=all&subsystem=all&search=&limit=20")
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, list)

        status, _ = self.request("GET", "/api/health", Origin="http://evil.example")
        self.assertEqual(status, 403)

        status, _ = self.request("GET", "/api/health", Host=f"evil.example:{self.port}")
        self.assertEqual(status, 403)

        status, _ = self.request("OPTIONS", "/api/health", Origin="http://127.0.0.1:5173")
        self.assertEqual(status, 204)

    def test_bundle_routes_return_safe_contracts(self) -> None:
        with Database(self.database_path) as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "symptom",
                        "graphics",
                        "crash",
                        "Game crash",
                        source="eventlog",
                        details={"message": r"Faulting application C:\Users\Raven\game.exe"},
                    ),
                    Event(
                        now,
                        "change",
                        "apps",
                        "updated",
                        "Chat app updated",
                        source="apps",
                    ),
                ]
            )
        status, payload = self.request("POST", "/api/export-bundle", {"days": 30})
        self.assertEqual(status, 200)
        self.assertEqual(payload["bundle"]["privacy"]["raw_messages"], "excluded")
        self.assertNotIn("Raven", json.dumps(payload))
        self.assertNotIn("Faulting application", json.dumps(payload))

        status, validation = self.request("POST", "/api/validate-bundle", {"bundle": payload["bundle"]})
        self.assertEqual(status, 200)
        self.assertTrue(validation["valid"])

    def test_body_and_query_limits_are_rejected(self) -> None:
        status, payload = self.request("GET", "/api/health?days=not-a-number")
        self.assertEqual(status, 400)
        self.assertIn("days", payload["error"])

        status, payload = self.request("POST", "/api/validate-bundle", ["not", "an", "object"])
        self.assertEqual(status, 400)
        self.assertIn("JSON object", payload["error"])

        status, payload = self.request(
            "POST",
            "/api/validate-bundle",
            {},
            **{"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 400)
        self.assertIn("application/json", payload["error"])

        for days in (0, -5, 3651):
            status, payload = self.request("POST", "/api/export-bundle", {"days": days})
            self.assertEqual(status, 400)
            self.assertIn("days must be between", payload["error"])

    def test_deeply_nested_json_body_returns_a_safe_error(self) -> None:
        depth = 2_000
        body = b'{"bundle":' + (b'{"nested":' * depth) + b"null" + (b"}" * depth) + b"}"
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(
            "POST",
            "/api/validate-bundle",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        connection.close()

        self.assertEqual(response.status, 200)
        self.assertFalse(payload["valid"])
        self.assertIn("Bundle nesting exceeds 64 levels", payload["errors"])

    def test_missing_host_header_is_rejected(self) -> None:
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.putrequest("GET", "/api/health", skip_host=True)
        connection.endheaders()
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        connection.close()

        self.assertEqual(response.status, 400)
        self.assertEqual(payload["error"], "Host header is required")

    def test_per_launch_token_protects_loopback_routes(self) -> None:
        token = "test-token-" + "a" * 32
        protected = UiServer(("127.0.0.1", 0), self.database_path, api_token=token)
        thread = threading.Thread(target=protected.serve_forever, daemon=True)
        thread.start()
        port = protected.server_address[1]

        def protected_request(headers: dict[str, str] | None = None):
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", "/api/health", headers=headers or {})
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
            connection.close()
            return response.status, payload

        try:
            connection = HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request(
                "OPTIONS",
                "/api/health",
                headers={
                    "Origin": "http://tauri.localhost",
                    "Access-Control-Request-Headers": "x-difftrail-token",
                },
            )
            response = connection.getresponse()
            response.read()
            connection.close()
            self.assertEqual(response.status, 204)

            status, payload = protected_request()
            self.assertEqual(status, 401)
            self.assertIn("token", payload["error"].casefold())

            status, _ = protected_request({"X-Difftrail-Token": "wrong-" + "b" * 32})
            self.assertEqual(status, 401)

            status, payload = protected_request({"X-Difftrail-Token": token})
            self.assertEqual(status, 200)
            self.assertEqual(payload["api_port"], port)
        finally:
            protected.shutdown()
            protected.server_close()
            thread.join(timeout=2)

    def test_non_ascii_api_token_is_rejected_at_startup(self) -> None:
        with self.assertRaisesRegex(ValueError, "ASCII"):
            UiServer(("127.0.0.1", 0), self.database_path, api_token="é" * 32)

    def test_ui_server_constructor_rejects_non_loopback_bindings(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            UiServer(("0.0.0.0", 0), self.database_path)

    @unittest.skipUnless(socket.has_ipv6, "IPv6 is unavailable")
    def test_ui_server_accepts_ipv6_loopback(self) -> None:
        server = UiServer(("::1", 0), self.database_path)
        try:
            self.assertEqual(server.server_address[0], "::1")
        finally:
            server.server_close()

    def test_scan_routes_bucket_provider_errors_without_returning_them(self) -> None:
        result = SimpleNamespace(
            as_dict=lambda: {
                "scan_id": "scan-safe-errors",
                "status": "partial",
                "sources": 1,
                "state_events": 0,
                "symptom_events": 0,
                "errors": [r"eventlog: C:\Users\Alice\Secret\provider.log"],
            }
        )
        with patch("difftrail.ui_api.run_automated_scan", return_value=result):
            for path, body in (("/api/scan", {}), ("/api/automation/watcher", {"action": "run"})):
                with self.subTest(path=path):
                    status, payload = self.request("POST", path, body)
                    self.assertEqual(status, 200)
                    encoded = json.dumps(payload)
                    self.assertNotIn("Alice", encoded)
                    self.assertNotIn(r"C:\Users", encoded)
                    self.assertEqual(payload["scan"]["errors"], [])
                    self.assertEqual(payload["scan"]["error_count"], 1)

    def test_public_event_metadata_and_detail_summary_hide_absolute_paths(self) -> None:
        with Database(self.database_path) as database:
            now = utc_now()
            database.save_events(
                [
                    Event(
                        now,
                        "change",
                        "general",
                        "updated",
                        "Synthetic event",
                        source="test",
                        details={"after": {"display_name": r"C:\Program Files\Secret\tool.exe"}},
                        event_id="public-redaction",
                    )
                ]
            )
            database.connection.execute(
                "UPDATE events SET source = ?, subsystem = ? WHERE id = ?",
                (r"C:\Users\Alice\Secret", r"C:\Users\Alice\Subsystem", "public-redaction"),
            )
            database.connection.commit()

        status, payload = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        encoded = json.dumps(payload)
        self.assertNotIn("Alice", encoded)
        self.assertNotIn(r"C:\Users", encoded)
        self.assertNotIn(r"C:\Program Files", encoded)

    def test_incident_routes_filter_malformed_stored_result_payloads(self) -> None:
        with Database(self.database_path) as database:
            now = utc_now()
            incident = database.create_incident(
                IncidentRequest("Investigate a display issue", now - timedelta(hours=1), now, "graphics", 7)
            )
            result = {
                "event": {
                    "id": r"C:\Users\Alice\event",
                    "occurred_at": now.isoformat(),
                    "kind": "change",
                    "subsystem": r"C:\Users\Alice\graphics",
                    "action": "updated",
                    "title": r"Changed C:\Program Files\Secret\tool.exe",
                    "entity": r"C:\Program Files\Secret\tool.exe",
                    "severity": "high",
                    "source": r"C:\Users\Alice\source",
                    "details": {"message": "private raw collector message"},
                },
                "score": float("inf"),
                "confidence": "High",
                "evidence": [
                    {
                        "signal": r"C:\Users\Alice\signal",
                        "strength": "strong",
                        "explanation": r"Review C:\Program Files\Secret\tool.exe",
                        "event_id": r"C:\Users\Alice\event",
                        "private_message": "private evidence payload",
                    }
                ],
                "counter_evidence": None,
                "next_action": r"Open C:\Program Files\Secret\tool.exe",
                "safe_diagnostic": {
                    "label": r"C:\Users\Alice\label",
                    "target": r"C:\Program Files\Secret\tool.exe",
                    "note": "private diagnostic note",
                },
            }
            database.connection.execute(
                "UPDATE incidents SET description = ?, result_json = ?, coverage_json = ? WHERE id = ?",
                (
                    r"Investigate C:\Users\Alice\private",
                    json.dumps([result]),
                    json.dumps(
                        {
                            "reasons": [r"Missing C:\Users\Alice\source"],
                            "scan_count": float("inf"),
                            "private_message": "secret",
                        }
                    ),
                    incident.id,
                ),
            )
            database.connection.commit()

        status, payload = self.request("GET", "/api/incidents")
        self.assertEqual(status, 200)
        self.assertEqual(payload[0]["results"][0]["score"], 0)
        self.assertEqual(payload[0]["coverage"]["scan_count"], 0)
        encoded = json.dumps(payload)
        for secret in ("Alice", r"C:\Users", r"C:\Program Files", "private raw collector", "private evidence payload"):
            self.assertNotIn(secret, encoded)

        status, payload = self.request(
            "POST",
            "/api/investigations",
            {"description": r"Investigate C:\Users\Alice\private", "subsystem": "graphics", "lookback_days": 7},
        )
        self.assertEqual(status, 200)
        self.assertNotIn("Alice", json.dumps(payload))
        self.assertNotIn(r"C:\Users", json.dumps(payload))

    def test_investigation_detail_and_feedback_routes(self) -> None:
        status, payload = self.request(
            "POST",
            "/api/investigations",
            {"description": "graphics are broken", "subsystem": "graphics", "lookback_days": 7},
        )
        self.assertEqual(status, 200)
        incident_id = payload["incident"]["id"]

        status, detail = self.request("GET", f"/api/incidents/{incident_id}")
        self.assertEqual(status, 200)
        self.assertEqual(detail["id"], incident_id)

        status, feedback = self.request(
            "POST",
            f"/api/incidents/{incident_id}/feedback",
            {"outcome": "unknown"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(feedback["incident"]["feedback"]["outcome"], "unknown")

        status, payload = self.request(
            "POST",
            f"/api/incidents/{incident_id}/feedback",
            {"outcome": "correct", "event_id": {"not": "a string"}},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "event_id must be a string")
