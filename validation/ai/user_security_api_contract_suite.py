from __future__ import annotations

import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.user_security_router import (
    UserSecurityAPIService,
    UserSecuritySnapshotStore,
    build_user_security_router,
)


# ================================================================
# HELPERS
# ================================================================


def heading(
    text: str,
):

    print()

    print(
        "=" * 112
    )

    print(
        text
    )

    print(
        "=" * 112
    )


def build_explanation(
    *,
    security_id: str = "USER-SEC-001",
    policy_decision: str = "PROTECT_PREVIEW",
    display_status: str = "PROTECTION_PREPARED",
):

    return {

        "schema_version":
            "sentinelx.ai.user-explanation.v1",

        "agent":
            "AIUserExplanationAgent",

        "agent_version":
            "7D.8-v1",

        "security_id":
            security_id,

        "event_id":
            f"{security_id}-EVENT",

        "incident_id":
            f"{security_id}-INCIDENT",

        "risk_level":
            "CRITICAL",

        "threat_assessment":
            "LIKELY_MALICIOUS",

        "risk_confidence":
            0.95,

        "protection_mode":
            "RECOMMENDED",

        "protection_mode_display":
            "Recommended",

        "policy_decision":
            policy_decision,

        "selected_plan_id":
            (
                "DT-PLAN-3"
                if policy_decision
                !=
                "MONITOR"
                else None
            ),

        "display_status":
            display_status,

        "requires_user_confirmation":
            (
                policy_decision
                ==
                "ASK_USER"
            ),

        "user_prompt":
            (
                "Review the simulated protection plan."
                if policy_decision
                ==
                "ASK_USER"
                else None
            ),

        "execution_message":
            (
                "Sentinel-X prepared a protection plan "
                "in simulation. No real containment or "
                "remediation action has been executed."
            ),

        "headline":
            "Likely malicious activity needs attention",

        "plain_language_summary":
            (
                "Sentinel-X observed several related "
                "security signals that together suggest "
                "likely malicious behavior."
            ),

        "why_flagged": [

            "Hidden encoded PowerShell execution was observed.",

            "File and persistence activity were also observed.",
        ],

        "why_it_matters":
            (
                "The combination can indicate an attempt "
                "to maintain access on the endpoint."
            ),

        "planned_actions": [

            {
                "action_type":
                    "TERMINATE_PROCESS",

                "action_label":
                    "End the suspicious process",

                "target": {

                    "pid":
                        5501,

                    "name":
                        "powershell.exe",
                },
            },

            {
                "action_type":
                    "QUARANTINE_FILE",

                "action_label":
                    "Quarantine the observed file",

                "target": {

                    "path":
                        "C:\\Users\\Public\\payload.bin",
                },
            },
        ],

        "recommended_action_explanation":
            (
                "The simulated plan proposes targeted "
                "containment while avoiding broader "
                "endpoint isolation."
            ),

        "uncertainty_note":
            (
                "The activity is likely malicious but "
                "is not described as confirmed malicious."
            ),

        "digital_twin_note":
            (
                "The Digital Twin result is a simulated "
                "estimate, not a guarantee of real-world "
                "outcome."
            ),

        "technical_details_available":
            True,

        "source_versions": {

            "risk":
                "7D.4-v3",

            "response":
                "7D.5-v2",

            "plan_selection":
                "7D.6-v1",

            "protection_policy":
                "7D.7-v1",
        },

        "simulation_only":
            True,

        "execution_allowed":
            False,

        "automatic_execution_allowed":
            False,

        "real_response_executed":
            False,

        "next_stage":
            "USER_FACING_API",
    }


# ================================================================
# MAIN
# ================================================================


def main():

    heading(
        (
            "SENTINEL-X 7D.9 — "
            "USER-FACING SECURITY API CONTRACT SUITE"
        )
    )


    store = (
        UserSecuritySnapshotStore()
    )


    service = (
        UserSecurityAPIService(
            store=store
        )
    )


    app = FastAPI()


    app.include_router(
        build_user_security_router(
            service
        )
    )


    client = (
        TestClient(
            app
        )
    )


    passed = 0

    total = 8


    # ============================================================
    # 1. STATUS
    # ============================================================

    heading(
        "API-01 — STATUS"
    )


    response = client.get(
        "/api/v1/user-security/status"
    )


    data = response.json()


    ok = (
        response.status_code
        ==
        200
        and
        data.get(
            "status"
        )
        ==
        "READY"
        and
        data.get(
            "read_only_http_api"
        )
        is True
        and
        data.get(
            "execution_allowed"
        )
        is False
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 2. MODES
    # ============================================================

    heading(
        "API-02 — PROTECTION MODES"
    )


    response = client.get(
        "/api/v1/user-security/protection-modes"
    )


    data = response.json()


    modes = (
        data.get(
            "modes"
        )
        or {}
    )


    ok = (
        response.status_code
        ==
        200
        and
        data.get(
            "count"
        )
        ==
        4
        and
        {
            "RECOMMENDED",
            "STRICT",
            "ASK_ME",
            "MONITOR_ONLY",
        }
        ==
        set(
            modes.keys()
        )
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 3. EMPTY LIST
    # ============================================================

    heading(
        "API-03 — EMPTY USER THREAT FEED"
    )


    response = client.get(
        "/api/v1/user-security/threats"
    )


    data = response.json()


    ok = (
        response.status_code
        ==
        200
        and
        data.get(
            "count"
        )
        ==
        0
        and
        data.get(
            "threats"
        )
        ==
        []
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 4. INTERNAL PUBLISH
    # ============================================================

    heading(
        "API-04 — INTERNAL SNAPSHOT PUBLISH"
    )


    explanation = (
        build_explanation()
    )


    snapshot = (
        service.publish_explanation(
            explanation
        )
    )


    ok = (
        snapshot.get(
            "security_id"
        )
        ==
        "USER-SEC-001"
        and
        snapshot.get(
            "status"
        )
        ==
        "PROTECTION_PREPARED"
        and
        snapshot.get(
            "execution_allowed"
        )
        is False
        and
        snapshot.get(
            "real_response_executed"
        )
        is False
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 5. LIST PUBLISHED SNAPSHOT
    # ============================================================

    heading(
        "API-05 — USER THREAT FEED"
    )


    response = client.get(
        "/api/v1/user-security/threats"
    )


    data = response.json()


    threats = (
        data.get(
            "threats"
        )
        or []
    )


    ok = (
        response.status_code
        ==
        200
        and
        data.get(
            "count"
        )
        ==
        1
        and
        threats
        and
        threats[
            0
        ].get(
            "security_id"
        )
        ==
        "USER-SEC-001"
        and
        "planned_actions"
        not in
        threats[
            0
        ]
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 6. DETAIL
    # ============================================================

    heading(
        "API-06 — USER THREAT DETAIL"
    )


    response = client.get(
        "/api/v1/user-security/threats/USER-SEC-001"
    )


    data = response.json()


    actions = (
        (
            data.get(
                "response"
            )
            or {}
        )
        .get(
            "planned_actions"
        )
        or []
    )


    ok = (
        response.status_code
        ==
        200
        and
        data.get(
            "status"
        )
        ==
        "PROTECTION_PREPARED"
        and
        len(
            actions
        )
        ==
        2
        and
        data.get(
            "simulation_only"
        )
        is True
        and
        data.get(
            "execution_allowed"
        )
        is False
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 7. NOT FOUND
    # ============================================================

    heading(
        "API-07 — UNKNOWN SECURITY ID"
    )


    response = client.get(
        "/api/v1/user-security/threats/DOES-NOT-EXIST"
    )


    ok = (
        response.status_code
        ==
        404
    )


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # 8. EXECUTION SAFETY
    # ============================================================

    heading(
        "API-08 — UNSAFE SNAPSHOT REJECTION"
    )


    unsafe = (
        build_explanation(
            security_id=
                "USER-SEC-UNSAFE"
        )
    )


    unsafe[
        "execution_allowed"
    ] = True


    rejected = False


    try:

        service.publish_explanation(
            unsafe
        )


    except ValueError:

        rejected = True


    ok = rejected


    print(
        "RESULT:",
        "PASS" if ok else "FAIL",
    )


    passed += int(
        ok
    )


    # ============================================================
    # FINAL
    # ============================================================

    heading(
        "7D.9 RESULT"
    )


    print(
        f"TOTAL : {passed}/{total} PASS"
    )


    if passed == total:

        print()

        print(
            "RESULT: PASS"
        )

        print(
            (
                "SENTINEL-X 7D.9 User-Facing "
                "Security APIs are ready to close."
            )
        )

        return 0


    print()

    print(
        "RESULT: FAIL"
    )

    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )
