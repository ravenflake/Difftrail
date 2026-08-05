import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from difftrail.db import Database
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
        status, payload = self.request("POST", "/api/export-bundle", {"days": 30})
        self.assertEqual(status, 200)
        self.assertTrue(payload["bundle"]["privacy"]["raw_messages"] == "excluded")

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
