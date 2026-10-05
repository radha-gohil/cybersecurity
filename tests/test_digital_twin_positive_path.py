
"""
SENTINEL-X — ISOLATED DIGITAL TWIN POSITIVE-PATH TESTS

Tests:
1. Incomplete investigation is blocked.
2. Failed evidence validation is blocked.
3. Completed validated investigation produces virtual scenarios.
4. Different risk inputs produce different heuristic baselines.
5. Preview does not mutate the synthetic source evidence.
6. Preview never authorizes responses or SOC promotion.

IMPORTANT:
- Uses entirely synthetic evidence in memory.
- No FastAPI requests.
- No database reads or writes.
- No actual endpoint response actions.
- SHADOW mode and production configuration are untouched.

Run from the repository root:
    python -m unittest tests.test_digital_twin_positive_path -v

Alternative:
    python tests/test_digital_twin_positive_path.py
"""

import copy
import sys
import unittest
from pathlib import Path


# Allow direct execution from the tests directory.
ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from response.digital_twin_visual_preview import (
    DigitalTwinVisualPreview,
)


def synthetic_evidence(
    device_id="SYNTHETIC-DEVICE-001",
    process_score=80,
    include_network=True,
):
    """
    Construct deliberately synthetic telemetry.

    Scores are invented for TEST FIXTURES ONLY.
    They are not claims about any real detection.
    """

    process = {
        "pid": 5252,
        "process_create_time": "2026-01-01T10:00:00Z",
        "device_id": device_id,
        "name": "synthetic-test-process.exe",
        "combined_threat_score": process_score,
        "behavior_score": process_score,
        "anomaly_score": 0,
        "source_mode": "SYNTHETIC_TEST",
    }

    network = []

    if include_network:
        network.append(
            {
                "device_id": device_id,
                "event_id": "SYNTHETIC-NETWORK-001",
                "remote_ip": "198.51.100.20",
                "remote_port": 443,
                "protocol": "TCP",
                "source_mode": "SYNTHETIC_TEST",
            }
        )

    return {
        "processes": [process],
        "files": [],
        "network_connections": network,
        "registry_artifacts": [],
    }


def synthetic_incident(
    incident_id,
    device_id="SYNTHETIC-DEVICE-001",
):
    """
    This record is never persisted.
    """
    return {
        "incident_id": incident_id,
        "device_id": device_id,
        "title": "Synthetic Digital Twin Test",
        "severity": "HIGH",
        "status": "NEW",
        "timeline": [],
        "test_fixture": True,
    }


def synthetic_intelligence(
    evidence,
    status="COMPLETED",
    passed=True,
):
    """
    Explicitly constructed test intelligence.

    A passing validation flag here is supplied by the
    test fixture, NOT produced by the real evidence
    validator.

    Therefore the positive test confirms integration
    behavior, not real evidence-quality correctness.
    """

    return {
        "status": status,
        "risk_score": None,
        "risk_level": "UNVALIDATED_TEST_INPUT",
        "evidence_validation": {
            "passed": passed,
            "validation_policy": "SYNTHETIC_FIXTURE",
            "authoritative_event_count": (
                2 if passed else 0
            ),
            "rejected_event_count": (
                0 if passed else 2
            ),
            "categories_by_device": (
                {
                    "SYNTHETIC-DEVICE-001": [
                        "PROCESS",
                        "NETWORK",
                    ]
                }
                if passed
                else {}
            ),
            "reasons": (
                []
                if passed
                else [
                    "Synthetic test validation failure."
                ]
            ),
        },
        "coordinated_analysis": {
            "evidence": copy.deepcopy(evidence),
            "agent_outputs": {},
        },
        "response": {
            "recommendations": [],
        },
        "test_fixture": True,
    }


class DigitalTwinPositivePathTests(unittest.TestCase):

    def setUp(self):
        self.engine = DigitalTwinVisualPreview()

    def run_preview(
        self,
        incident_id,
        status="COMPLETED",
        passed=True,
        process_score=80,
        include_network=True,
    ):
        evidence = synthetic_evidence(
            process_score=process_score,
            include_network=include_network,
        )

        incident = synthetic_incident(incident_id)

        intelligence = synthetic_intelligence(
            evidence=evidence,
            status=status,
            passed=passed,
        )

        before_incident = copy.deepcopy(incident)
        before_intelligence = copy.deepcopy(intelligence)

        result = self.engine.evaluate(
            incident,
            intelligence,
        )

        self.assertEqual(incident, before_incident)
        self.assertEqual(
            intelligence,
            before_intelligence,
        )

        self.assertEqual(
            result["incident_id"],
            incident_id,
        )

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

        return result

    def test_01_incomplete_investigation(self):

        result = self.run_preview(
            "SYNTHETIC-INCOMPLETE",
            status="INCOMPLETE",
            passed=False,
        )

        self.assertFalse(
            result["plan_evaluation_eligible"]
        )
        self.assertEqual(
            result["plans_evaluated"],
            0,
        )
        self.assertEqual(
            result["ranked_plans"],
            [],
        )
        self.assertIsNone(
            result["best_plan"]
        )
        self.assertEqual(
            result["decision"],
            "INCOMPLETE_INVESTIGATION",
        )

    def test_02_failed_evidence_gate(self):

        result = self.run_preview(
            "SYNTHETIC-FAILED-EVIDENCE",
            status="COMPLETED",
            passed=False,
        )

        self.assertFalse(
            result["plan_evaluation_eligible"]
        )
        self.assertEqual(
            result["plans_evaluated"],
            0,
        )
        self.assertEqual(
            result["decision"],
            "INSUFFICIENT_AUTHORITATIVE_EVIDENCE",
        )

    def test_03_completed_validated_investigation(self):

        result = self.run_preview(
            "SYNTHETIC-ELIGIBLE",
            status="COMPLETED",
            passed=True,
            process_score=80,
            include_network=True,
        )

        self.assertTrue(
            result["plan_evaluation_eligible"]
        )

        self.assertGreater(
            result["plans_evaluated"],
            0,
        )

        plans = result["ranked_plans"]

        self.assertEqual(
            len(plans),
            result["plans_evaluated"],
        )

        self.assertIsNotNone(
            result["best_plan"]
        )

        self.assertEqual(
            result["decision"],
            "HYPOTHETICAL_PLAN_COMPARISON_ONLY",
        )

        # The synthetic process has a test threat score,
        # so blocking one network connection must not
        # be interpreted as removing process risk.
        self.assertGreater(
            result["initial_risk_score"],
            0,
        )

        for plan in plans:

            self.assertTrue(
                plan["hypothetical"]
            )

            self.assertFalse(
                plan["approval_eligible"]
            )

            self.assertGreaterEqual(
                len(plan["playback"]),
                2,
            )

            self.assertEqual(
                plan["playback"][0]["action_type"],
                "BASELINE",
            )

            self.assertEqual(
                len(plan["playback"]),
                len(plan["actions"]) + 1,
            )

            for frame in plan["playback"]:

                self.assertIn(
                    "risk_score",
                    frame,
                )

                self.assertIn(
                    "state",
                    frame,
                )

                self.assertIn(
                    "success",
                    frame,
                )

    def test_04_different_process_scores(self):

        high = self.run_preview(
            "SYNTHETIC-HIGH",
            process_score=80,
        )

        low = self.run_preview(
            "SYNTHETIC-LOW",
            process_score=20,
        )

        self.assertGreater(
            high["initial_risk_score"],
            low["initial_risk_score"],
        )

        self.assertNotEqual(
            high["initial_risk_score"],
            low["initial_risk_score"],
        )

        # These are heuristic scores, not probabilities.
        self.assertEqual(
            high["model_type"],
            "HEURISTIC_DIGITAL_TWIN_V1",
        )
        self.assertEqual(
            low["model_type"],
            "HEURISTIC_DIGITAL_TWIN_V1",
        )

    def test_05_no_network_scenario(self):

        result = self.run_preview(
            "SYNTHETIC-PROCESS-ONLY",
            process_score=70,
            include_network=False,
        )

        self.assertTrue(
            result["plan_evaluation_eligible"]
        )

        action_types = {
            action.get("action_type")
            for plan in result["ranked_plans"]
            for action in plan.get("actions", [])
        }

        # No network connection was provided,
        # therefore no network block should be offered.
        self.assertNotIn(
            "BLOCK_NETWORK",
            action_types,
        )

    def test_06_incomplete_with_high_score(self):

        result = self.run_preview(
            "SYNTHETIC-HIGH-BUT-INCOMPLETE",
            status="INCOMPLETE",
            passed=False,
            process_score=95,
        )

        # High modeled score must never bypass the
        # evidence gate.
        self.assertGreater(
            result["initial_risk_score"],
            0,
        )

        self.assertEqual(
            result["plans_evaluated"],
            0,
        )

        self.assertFalse(
            result["response_authorized"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
