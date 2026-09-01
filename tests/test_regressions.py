"""Pruebas de regresion para entradas HTTP y persistencia."""

import os
import tempfile
import unittest

import app as app_module
import fingerprint
from core import identity, store
from sniffer import TrafficMonitor


class RegressionTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(prefix="netscope-regression-", suffix=".db")
        os.close(fd)
        os.remove(self.db_path)
        store.DB = self.db_path
        store.init()
        app_module.SITE = store.ensure_site("test")
        app_module._last_scan.update({
            "devices": [], "gateway": "", "ts": 0, "enriching": False,
            "error": "", "by_identity": {}, "known_ids": set(),
        })
        self.client = app_module.app.test_client()

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except FileNotFoundError:
                pass

    def test_malformed_json_returns_validation_error(self):
        response = self.client.post(
            "/api/deepscan", data="{", content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "falta ip")

    def test_invalid_identity_payload_does_not_raise(self):
        response = self.client.post("/api/block/start", json={"identity_id": "abc"})
        self.assertEqual(response.status_code, 409)
        response = self.client.post("/api/block/start", json={"ip": ["192.168.1.2"]})
        self.assertEqual(response.status_code, 409)

    def test_string_false_is_not_treated_as_true(self):
        identity_id = store.create_identity(app_module.SITE, "equipo")
        response = self.client.post(
            f"/api/device/{identity_id}/trust", json={"trusted": "false"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(store.get_identity(identity_id)["trusted"], 0)

    def test_pages_render_and_foreign_host_is_rejected(self):
        for path in ("/", "/devices", "/traffic", "/speed", "/history",
                     "/settings", "/system", "/wifiscan", "/deepscan"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
        response = self.client.get("/", headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 403)

    def test_history_is_isolated_by_site(self):
        other_site = store.ensure_site("otro")
        identity_id = store.create_identity(other_site, "ajeno")
        response = self.client.get(
            f"/api/history/traffic?identity_id={identity_id}&days=7")
        self.assertEqual(response.status_code, 404)

    def test_csv_neutralizes_spreadsheet_formulas(self):
        store.create_identity(app_module.SITE, "=1+1")
        body = self.client.get("/api/export/devices.csv").get_data(as_text=True)
        self.assertIn("'=1+1", body)

    def test_upnp_description_must_stay_on_target(self):
        self.assertTrue(fingerprint._safe_device_url(
            "http://192.168.1.20/device.xml", "192.168.1.20"))
        self.assertFalse(fingerprint._safe_device_url(
            "http://127.0.0.1/admin", "192.168.1.20"))
        self.assertFalse(fingerprint._safe_device_url(
            "https://192.168.1.20/device.xml", "192.168.1.20"))

    def test_invalid_port_set_is_ignored(self):
        signals = identity.signals_from_observation(
            {"mac": "00:11:22:33:44:55", "port_set": ["invalid"]})
        self.assertEqual([kind for kind, _, _ in signals], ["mac"])

    def test_traffic_cache_is_bounded_and_keeps_local_devices(self):
        monitor = TrafficMonitor()
        monitor.MAX_STATS = 10
        monitor.set_local_context({"192.168.1.2"}, ["192.168.1.0/24"])
        with monitor._lock:
            monitor.stats["192.168.1.20"] = [1, 1, 1, 0, 1.0]
            for index in range(20):
                monitor.stats[f"8.8.8.{index}"] = [1, 1, 1, 0, float(index)]
            monitor._prune_stats_locked()
        self.assertIn("192.168.1.20", monitor.stats)
        self.assertLessEqual(len(monitor.stats), 10)

    def test_merge_preserves_ports_facts_and_events(self):
        keep = store.create_identity(app_module.SITE, "principal")
        drop = store.create_identity(app_module.SITE, "secundaria")
        store.set_ports(drop, [{"port": 443, "proto": "tcp", "service": "https"}])
        store.set_fact(drop, "model_name", "TV")
        store.record_event(app_module.SITE, drop, "prueba")
        self.assertTrue(store.merge_identities(keep, drop))
        self.assertEqual(store.ports_of(keep)[0]["port"], 443)
        self.assertEqual(store.facts_of(keep)["model_name"], "TV")
        self.assertEqual(store.list_events(app_module.SITE)[0]["identity_id"], keep)
        self.assertIsNone(store.get_identity(drop))


if __name__ == "__main__":
    unittest.main()
