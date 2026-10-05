
"""
SENTINEL-X Digital Twin V2 regression tests.

Run:
python -m unittest discover -s tests \
    -p "test_digital_twin_v2.py" -v

Windows PowerShell single line:
python -m unittest discover -s tests -p "test_digital_twin_v2.py" -v

No production database access or API calls.
"""

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from response.digital_twin_visual_preview import (
    DigitalTwinVisualPreview,
)


def evidence(
    score=70,
    pid=5252,
    create_time="2026-01-01T10:00:00Z",
    mode="SYNTHETIC_TEST",
    network=True,
):
    processes = [{
        "pid": pid,
        "process_create_time": create_time,
        "device_id": "TEST-DEVICE",
        "combined_threat_score": score,
        "behavior_score": score,
        "source_mode": mode,
    }]

    connections = []

    if network:
        connections.append({
            "device_id": "TEST-DEVICE",
            "event_id": "TEST-NETWORK-1",
            "remote_ip": "198.51.100.20",
            "remote_port": 443,
            "source_mode": mode,
        })

    return {
        "processes": processes,
        "files": [],
        "network_connections": connections,
        "registry_artifacts": [],
    }


def intelligence(
    input_evidence,
    status="COMPLETED",
    passed=True,
):
    return {
        "status": status,
        "risk_score": None,
        "evidence_validation": {
            "passed": passed,
            "validation_policy": "TEST_FIXTURE",
            "authoritative_event_count":
                2 if passed else 0,
        },
        "coordinated_analysis": {
            "evidence": copy.deepcopy(
                input_evidence
            ),
        },
    }


class DigitalTwinV2Tests(unittest.TestCase):

    def setUp(self):
        self.engine = DigitalTwinVisualPreview()

    def evaluate(
        self,
        test_id,
        source,
        status="COMPLETED",
        passed=True,
        timeline=None,
    ):
        incident = {
            "incident_id": test_id,
            "timeline": timeline or [],
        }
        intel = intelligence(
            source,
            status=status,
            passed=passed,
        )

        original_incident = copy.deepcopy(incident)
        original_intel = copy.deepcopy(intel)

        result = self.engine.evaluate(
            incident,
            intel,
        )

        # Input objects must not be mutated.
        self.assertEqual(
            incident,
            original_incident,
        )
        self.assertEqual(
            intel,
            original_intel,
        )

        # Every preview remains non-authoritative.
        self.assertTrue(result["preview_only"])
        self.assertTrue(result["simulation_mode"])
        self.assertFalse(
            result["real_endpoint_modified"]
        )
        self.assertFalse(
            result["soc_case_created"]
        )
        self.assertFalse(
            result["approval_eligible"]
        )
        self.assertFalse(
            result["response_authorized"]
        )

        self.assertEqual(
            result["plans_evaluated"],
            len(result["ranked_plans"]),
        )

        return result

    def test_01_incomplete_is_blocked(self):
        result = self.evaluate(
            "V2-INCOMPLETE",
            evidence(score=95),
            status="INCOMPLETE",
            passed=False,
        )

        self.assertEqual(
            result["plans_evaluated"], 0
        )
        self.assertEqual(
            result["decision"],
            "INCOMPLETE_INVESTIGATION",
        )

    def test_02_failed_validation_is_blocked(self):
        result = self.evaluate(
            "V2-FAILED",
            evidence(),
            status="COMPLETED",
            passed=False,
        )

        self.assertEqual(
            result["plans_evaluated"], 0
        )
        self.assertEqual(
            result["decision"],
            "INSUFFICIENT_AUTHORITATIVE_EVIDENCE",
        )

    def test_03_validated_scenario(self):
        result = self.evaluate(
            "V2-VALID",
            evidence(),
        )

        self.assertGreater(
            result["plans_evaluated"], 0
        )
        self.assertEqual(
            result["decision"],
            "HYPOTHETICAL_PLAN_COMPARISON_ONLY",
        )

        for plan in result["ranked_plans"]:
            self.assertTrue(
                plan["hypothetical"]
            )
            self.assertFalse(
                plan["approval_eligible"]
            )
            self.assertEqual(
                len(plan["playback"]),
                len(plan["actions"]) + 1,
            )
            self.assertIn(
                "residual_components",
                plan,
            )
            self.assertEqual(
                plan["score_type"],
                "HEURISTIC_RANKING_SCORE",
            )

    def test_04_risk_components_vary(self):
        high = self.evaluate(
            "V2-HIGH",
            evidence(score=90),
        )

        low = self.evaluate(
            "V2-LOW",
            evidence(score=20),
        )

        self.assertGreater(
            high["initial_risk_score"],
            low["initial_risk_score"],
        )

        self.assertGreater(
            high["baseline_risk_components"]["process"],
            low["baseline_risk_components"]["process"],
        )

    def test_05_shadow_entities_not_targeted(self):
        result = self.evaluate(
            "V2-SHADOW",
            evidence(mode="SHADOW_VALIDATION"),
        )

        self.assertEqual(
            result["plans_evaluated"], 0
        )
        self.assertEqual(
            result["candidate_actions"], []
        )

        self.assertEqual(
            result["decision"],
            "NO_EVALUABLE_VIRTUAL_PLAN",
        )

    def test_06_unreliable_process_id(self):
        source = evidence(
            pid=4,
            network=False,
        )

        result = self.evaluate(
            "V2-UNRELIABLE-PID",
            source,
        )

        self.assertEqual(
            result["candidate_actions"], []
        )
        self.assertEqual(
            result["plans_evaluated"], 0
        )

    def test_07_missing_creation_time(self):
        result = self.evaluate(
            "V2-NO-CREATE-TIME",
            evidence(
                create_time=None,
                network=False,
            ),
        )

        self.assertEqual(
            result["plans_evaluated"], 0
        )

    def test_08_info_network_not_targeted(self):
        source = evidence(
            network=True,
        )

        source["network_connections"][0][
            "observed_severity"
        ] = "INFO"

        source["processes"] = []

        result = self.evaluate(
            "V2-NETWORK-INFO",
            source,
        )

        self.assertEqual(
            result["candidate_actions"], []
        )
        self.assertEqual(
            result["plans_evaluated"], 0
        )

    def test_09_missing_network_evidence(self):
        result = self.evaluate(
            "V2-NO-NETWORK",
            evidence(network=False),
        )

        types = {
            action.get("action_type")
            for action in result["candidate_actions"]
        }

        self.assertNotIn(
            "BLOCK_NETWORK",
            types,
        )

    def test_10_unlinked_timeline_entity(self):
        source = evidence(network=False)

        timeline = [{
            "event_id": "DIFFERENT-EVENT",
            "event_category": "PROCESS",
            "severity": "HIGH",
            "device_id": "TEST-DEVICE",
        }]

        result = self.evaluate(
            "V2-UNLINKED",
            source,
            timeline=timeline,
        )

        self.assertEqual(
            result["plans_evaluated"], 0
        )

    def test_11_playback_components(self):
        result = self.evaluate(
            "V2-PLAYBACK",
            evidence(score=80),
        )

        self.assertGreater(
            result["plans_evaluated"], 0
        )

        for plan in result["ranked_plans"]:
            frames = plan["playback"]

            self.assertEqual(
                frames[0]["action_type"],
                "BASELINE",
            )

            for frame in frames:
                self.assertTrue(
                    frame["virtual_only"]
                )
                self.assertIn(
                    "risk_components",
                    frame,
                )
                self.assertIn(
                    "state",
                    frame,
                )

    def test_12_no_proven_mitigation_claim(self):
        result = self.evaluate(
            "V2-LIMITATIONS",
            evidence(),
        )

        self.assertEqual(
            result["risk_semantics"],
            "MODELED_HEURISTIC_COMPONENTS",
        )

        self.assertIn(
            "not AI outcome",
            " ".join(result["limitations"]),
        )

        for plan in result["ranked_plans"]:
            self.assertEqual(
                plan["reduction_semantics"],
                "REDUCTION_OF_MODELED_COMPONENTS",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
