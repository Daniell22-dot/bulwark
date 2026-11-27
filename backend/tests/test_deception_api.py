import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main


class DeceptionApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.patches = patch.multiple(
            main,
            DB_PATH=self.db_path,
            DECEPTION_API_KEY="test-api-key",
        )
        self.patches.start()
        self.client_context = TestClient(main.app)
        self.client = self.client_context.__enter__()

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.patches.stop()
        self.temp_dir.cleanup()

    def test_event_requires_api_key_and_persists_only_validated_fields(self):
        event = {
            "decoy_id": "pilot.desktop.01",
            "event_type": "file_opened",
            "occurred_at": "2026-11-27T15:00:00Z",
            "host_id": "workstation-01",
            "process_name": "unknown.exe",
        }

        rejected = self.client.post("/api/deception/events", json=event)
        self.assertEqual(rejected.status_code, 401)

        accepted = self.client.post(
            "/api/deception/events",
            json=event,
            headers={"X-API-Key": "test-api-key"},
        )
        self.assertEqual(accepted.status_code, 201)
        self.assertEqual(accepted.json()["status"], "accepted")

        listed = self.client.get(
            "/api/deception/events",
            headers={"X-API-Key": "test-api-key"},
        )
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()["events"]), 1)
        self.assertEqual(listed.json()["events"][0]["decoy_id"], "pilot.desktop.01")

    def test_rejects_untrusted_event_types_and_extra_payload_data(self):
        headers = {"X-API-Key": "test-api-key"}
        invalid_type = self.client.post(
            "/api/deception/events",
            json={"decoy_id": "decoy-1", "event_type": "credential_dump"},
            headers=headers,
        )
        extra_data = self.client.post(
            "/api/deception/events",
            json={
                "decoy_id": "decoy-1",
                "event_type": "callback",
                "credential": "must-not-be-sent",
            },
            headers=headers,
        )
        self.assertEqual(invalid_type.status_code, 422)
        self.assertEqual(extra_data.status_code, 422)

    def test_endpoint_is_disabled_without_configured_key(self):
        with patch.object(main, "DECEPTION_API_KEY", None):
            response = self.client.get("/api/deception/events")
        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
