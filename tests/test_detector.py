import unittest

from src.detector import detect
from src.models import AuthEvent, parse_utc
from src.reporting import portfolio_metrics, render_markdown


def make_event(**changes):
    values = {
        "event_id": "e1",
        "timestamp": "2026-09-01T09:00:00Z",
        "user": "user@example.invalid",
        "source_ip": "198.51.100.1",
        "result": "success",
        "mfa_state": "satisfied",
        "auth_method": "fido2",
        "device_trust": True,
        "conditional_access_applied": True,
        "risk_level": "low",
        "country": "IE",
        "app": "Synthetic App",
    }
    values.update(changes)
    return AuthEvent(**values)


class DetectionTests(unittest.TestCase):
    def test_timezone_normalization(self):
        self.assertEqual(parse_utc("2026-09-01T10:00:00+01:00").hour, 9)

    def test_invalid_state_is_rejected(self):
        with self.assertRaises(ValueError):
            make_event(mfa_state="invalid")

    def test_strong_authentication_is_clean(self):
        self.assertEqual(detect([make_event()]), [])

    def test_missing_mfa_assurance_is_flagged(self):
        findings = detect([make_event(mfa_state="not_satisfied", conditional_access_applied=False, risk_level="high", device_trust=False)])
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(findings[0].score, 85)

    def test_sequence_correlation(self):
        events = [
            make_event(event_id="a", result="failure", mfa_state="not_satisfied"),
            make_event(event_id="b", timestamp="2026-09-01T09:05:00Z", result="interrupted", mfa_state="not_satisfied"),
            make_event(event_id="c", timestamp="2026-09-01T09:10:00Z"),
        ]
        self.assertTrue(any("sequence" in f.title.lower() for f in detect(events)))

    def test_ids_are_deterministic(self):
        item = make_event(mfa_state="not_required", conditional_access_applied=False)
        self.assertEqual(detect([item])[0].finding_id, detect([item])[0].finding_id)

    def test_metrics_are_bounded(self):
        metrics = portfolio_metrics(detect([make_event(mfa_state="not_satisfied", conditional_access_applied=False, risk_level="high")]))
        self.assertLessEqual(metrics["highest_score"], 100)
        self.assertEqual(metrics["affected_users"], 1)

    def test_report_contains_caveat(self):
        text = render_markdown(detect([make_event(mfa_state="not_required", conditional_access_applied=False)]))
        self.assertIn("not proof", text)


if __name__ == "__main__":
    unittest.main()
