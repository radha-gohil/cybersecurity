from __future__ import annotations

import json
import sys
import time

from agents.ai_digital_twin_plan_selection_agent import (
    AIDigitalTwinPlanSelectionAgent,
)


def heading(text: str):
    print()
    print("=" * 110)
    print(text)
    print("=" * 110)


def show(value):
    print(json.dumps(value, indent=2, default=str))


def build_threat():
    return {
        "id": "DT-AI-001",
        "detection_id": 7001,
        "event_id": "DT-AI-EVENT-001",
        "incident_id": "DT-AI-INC-001",
        "device_id": "endpoint-01",
        "category": "PROCESS",
        "event_type": "process_start",
        "threat_type": "MULTI_STAGE_SUSPICIOUS_ACTIVITY",
        "severity": "CRITICAL",
        "verdict": "LIKELY_THREAT",
        "confidence": 0.95,
    }


def build_evidence():
    return {
        "processes": [
            {
                "pid": 5501,
                "name": "powershell.exe",
                "exe": (
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                    "powershell.exe"
                ),
                "process_create_time": 1791400000.0,
                "device_id": "endpoint-01",
                "combined_threat_score": 92,
                "threat_type": "SUSPICIOUS_POWERSHELL",
            }
        ],
        "files": [
            {
                "path": "C:\\Users\\Public\\payload.bin",
                "sha256": "a" * 64,
                "device_id": "endpoint-01",
                "static_risk_score": 80,
            }
        ],
        "network_connections": [
            {
                "remote_ip": "203.0.113.90",
                "remote_port": 443,
                "pid": 5501,
                "process_name": "powershell.exe",
                "device_id": "endpoint-01",
            }
        ],
        "registry_artifacts": [
            {
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "Updater",
                "value_data": "C:\\Users\\Public\\payload.bin",
                "data": "C:\\Users\\Public\\payload.bin",
                "device_id": "endpoint-01",
            }
        ],
    }


def build_risk():
    return {
        "agent": "AIRiskReasoningAgent",
        "agent_version": "7D.4-v3",
        "risk_score": 92.0,
        "risk_level": "CRITICAL",
        "confidence": 0.95,
        "threat_assessment": "LIKELY_MALICIOUS",
        "evidence_strength": "STRONG",
        "risk_summary": [
            "Multiple endpoint categories corroborate likely malicious behavior."
        ],
        "primary_risk_drivers": [
            "Hidden suspicious PowerShell execution",
            "Observed file artifact",
            "Observed outbound network connection",
            "Observed persistence modification",
        ],
        "uncertainties": [
            "Remote destination intent is not independently established"
        ],
        "why_this_level": (
            "Strong multi-source endpoint evidence warrants critical review priority."
        ),
        "risk_score_semantics": "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
        "action_selected": False,
        "simulation_only": True,
        "execution_allowed": False,
    }


def recommendation_item(action, priority, target_reference, target, reason):
    return {
        "action": action,
        "priority": priority,
        "reason": reason,
        "target_reference": target_reference,
        "target": target,
        "requires_approval": True,
        "digital_twin_candidate": True,
        "execution_allowed": False,
    }


def build_targeted_response(include_isolation: bool):
    evidence = build_evidence()
    recommendations = [
        recommendation_item(
            "PROCESS_TERMINATION_REVIEW",
            "HIGH",
            "PROCESS",
            {"processes": [evidence["processes"][0]]},
            "Review termination of the observed suspicious process.",
        ),
        recommendation_item(
            "QUARANTINE_REVIEW",
            "HIGH",
            "FILE",
            {"files": [evidence["files"][0]]},
            "Review quarantine of the observed file artifact.",
        ),
        recommendation_item(
            "PERSISTENCE_REMEDIATION_REVIEW",
            "HIGH",
            "PERSISTENCE",
            {"registry_artifacts": [evidence["registry_artifacts"][0]]},
            "Review remediation of observed persistence.",
        ),
        recommendation_item(
            "NETWORK_BLOCK_REVIEW",
            "MEDIUM",
            "NETWORK",
            {"connections": [evidence["network_connections"][0]]},
            "Review blocking the observed external connection.",
        ),
    ]

    if include_isolation:
        recommendations.append(
            recommendation_item(
                "ENDPOINT_ISOLATION_REVIEW",
                "CRITICAL",
                "ENDPOINT",
                {"device_id": "endpoint-01"},
                "Review endpoint isolation as the broad containment option.",
            )
        )

    return {
        "schema_version": "sentinelx.ai.response-recommendation.v1",
        "agent": "AIResponseRecommendationAgent",
        "agent_version": "7D.5-v2",
        "ai_available": True,
        "response_strategy": "CONTAINMENT_REVIEW" if include_isolation else "TARGETED_RESPONSE",
        "confidence": 0.93,
        "response_summary": [
            "Evidence-backed response candidates are available for Digital Twin evaluation."
        ],
        "recommendations": recommendations,
        "why_this_response": "Use simulated response planning before any execution.",
        "why_not_more_aggressive": "The Digital Twin should compare operational impact.",
        "why_not_less_aggressive": "Strong evidence justifies response simulation.",
        "recommendation_count": len(recommendations),
        "digital_twin_required": True,
        "next_stage": "DIGITAL_TWIN",
        "simulation_only": True,
        "execution_allowed": False,
        "automatic_execution_allowed": False,
        "real_response_executed": False,
    }


def build_monitor_response():
    return {
        "agent": "AIResponseRecommendationAgent",
        "agent_version": "7D.5-v2",
        "response_strategy": "INVESTIGATE",
        "recommendations": [
            {
                "action": "INVESTIGATE_INCIDENT",
                "priority": "MEDIUM",
                "target_reference": "NONE",
                "target": {},
                "requires_approval": False,
                "digital_twin_candidate": False,
                "execution_allowed": False,
            }
        ],
        "digital_twin_required": False,
        "simulation_only": True,
        "execution_allowed": False,
    }


def validate_selected_result(result, allow_isolation: bool):
    failures = []

    if result.get("ai_available") is not True:
        failures.append("AI unavailable.")
    if result.get("agent_version") != "7D.6-v1":
        failures.append("Wrong 7D.6 agent version.")
    if result.get("selection_status") != "SELECTED":
        failures.append("Plan was not selected.")
    if result.get("simulation_only") is not True:
        failures.append("simulation_only != True")
    if result.get("execution_allowed") is not False:
        failures.append("execution_allowed != False")
    if result.get("automatic_execution_allowed") is not False:
        failures.append("automatic_execution_allowed != False")
    if result.get("real_response_executed") is not False:
        failures.append("real_response_executed != False")

    dt = result.get("digital_twin") or {}
    ranked = dt.get("ranked_plans") or []
    ids = {plan.get("plan_id") for plan in ranked}
    selected_id = result.get("selected_plan_id")
    selected = result.get("selected_plan") or {}

    if not ranked:
        failures.append("Digital Twin produced no ranked plans.")
    if selected_id not in ids:
        failures.append("AI selected plan ID not present in Digital Twin output.")
    if selected.get("plan_id") != selected_id:
        failures.append("Hydrated selected plan does not match selected_plan_id.")
    if selected.get("real_endpoint_modified") is not False:
        failures.append("Selected plan modified a real endpoint.")

    action_types = {
        item.get("action_type")
        for item in selected.get("actions", [])
    }

    if not allow_isolation and "ISOLATE_ENDPOINT" in action_types:
        failures.append("Isolation appeared without a 7D.5 isolation candidate.")

    if "ISOLATE_ENDPOINT" in action_types:
        if result.get("isolation_justified") is not True:
            failures.append("Isolation selected without AI justification.")
    elif result.get("isolation_justified") is not False:
        failures.append("isolation_justified=True for non-isolation plan.")

    return failures


def main():
    heading("SENTINEL-X 7D.6 — DIGITAL TWIN + AI PLAN SELECTION SUITE")

    agent = AIDigitalTwinPlanSelectionAgent()
    threat = build_threat()
    risk = build_risk()
    evidence = build_evidence()

    passed = 0

    # ------------------------------------------------------------
    # Scenario 0: non-disruptive response must skip DT + AI.
    # ------------------------------------------------------------
    heading("DT-AI-00 — Non-disruptive response bypass")
    skipped = agent.select_plan(
        threat=threat,
        risk_assessment=risk,
        response_recommendation=build_monitor_response(),
        enriched_evidence=evidence,
    )
    show(skipped)
    skip_ok = (
        skipped.get("selection_status") == "NOT_REQUIRED"
        and skipped.get("selected_plan") is None
        and skipped.get("execution_allowed") is False
    )
    print("SCENARIO RESULT:", "PASS" if skip_ok else "FAIL")
    if skip_ok:
        passed += 1

    # ------------------------------------------------------------
    # Scenario 1: targeted remediation only.
    # ------------------------------------------------------------
    heading("DT-AI-01 — Targeted plans without isolation")
    targeted = agent.select_plan(
        threat=threat,
        risk_assessment=risk,
        response_recommendation=build_targeted_response(False),
        enriched_evidence=evidence,
    )
    show(targeted)
    failures = validate_selected_result(targeted, allow_isolation=False)
    if failures:
        print("SCENARIO RESULT: FAIL")
        for item in failures:
            print(" -", item)
    else:
        print("SCENARIO RESULT: PASS")
        passed += 1

    print("Waiting 6 seconds...")
    time.sleep(6)

    # ------------------------------------------------------------
    # Scenario 2: isolation is available, but not mandatory.
    # ------------------------------------------------------------
    heading("DT-AI-02 — Isolation available as a simulated option")
    isolation = agent.select_plan(
        threat=threat,
        risk_assessment=risk,
        response_recommendation=build_targeted_response(True),
        enriched_evidence=evidence,
    )
    show(isolation)
    failures = validate_selected_result(isolation, allow_isolation=True)
    if failures:
        print("SCENARIO RESULT: FAIL")
        for item in failures:
            print(" -", item)
    else:
        print("SCENARIO RESULT: PASS")
        passed += 1

    heading("7D.6 RESULT")
    print(f"TOTAL : {passed}/3 PASS")

    if passed == 3:
        print("RESULT: PASS")
        print("SENTINEL-X 7D.6 Digital Twin + AI Plan Selection is ready to close.")
        return 0

    print("RESULT: FAIL")
    print("Do not proceed to Protection Modes yet.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
