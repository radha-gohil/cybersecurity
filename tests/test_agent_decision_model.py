from agents.agent_decision import (
    AgentDecision,
)

from agents.decision_factory import (
    DecisionFactory,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X AGENT DECISION MODEL TEST"
    )
    print("=" * 80)


    # ============================================================
    # TRIAGE OUTPUT
    # ============================================================

    triage = {

        "priority":
            "P1",

        "triage_score":
            95,

        "requires_investigation":
            True,

        "categories": [

            "PROCESS",

            "FILE",

            "NETWORK",

            "REGISTRY",
        ],

        "malware_probability":
            0.94,

        "reasons": [

            "Critical incident.",

            "Multiple telemetry categories.",
        ],
    }


    # ============================================================
    # INVESTIGATION OUTPUT
    # ============================================================

    investigation = {

        "priority":
            "IMMEDIATE",

        "requires_response":
            True,

        "event_count":
            4,

        "category_counts": {

            "PROCESS":
                1,

            "FILE":
                1,

            "NETWORK":
                1,

            "REGISTRY":
                1,
        },

        "indicators": [

            "suspicious_execution",

            "persistence",
        ],

        "findings": [

            "Multiple correlated security activities detected.",

            "Network and persistence behavior observed.",
        ],
    }


    # ============================================================
    # RISK OUTPUT
    # ============================================================

    risk = {

        "risk_score":
            96,

        "risk_level":
            "CRITICAL",

        "requires_response":
            True,

        "recommended_action":
            "Immediate analyst review and containment recommendation.",

        "reasons": [

            "High malware probability.",

            "Persistence detected.",

            "Network activity detected.",
        ],

        "components": {

            "malware_probability": {

                "value":
                    0.94,

                "points":
                    20,
            },

            "persistence": {

                "value":
                    True,

                "points":
                    10,
            },
        },
    }


    # ============================================================
    # CREATE STANDARD DECISIONS
    # ============================================================

    triage_decision = (
        DecisionFactory.from_triage(
            triage
        )
    )


    investigation_decision = (
        DecisionFactory.from_investigation(
            investigation
        )
    )


    risk_decision = (
        DecisionFactory.from_risk(
            risk
        )
    )


    decisions = [

        triage_decision,

        investigation_decision,

        risk_decision,
    ]


    # ============================================================
    # PRINT DECISIONS
    # ============================================================

    for decision in decisions:

        data = (
            decision.to_dict()
        )


        print()
        print("-" * 80)

        print(
            "Agent:",
            data[
                "agent"
            ],
        )

        print(
            "Decision:",
            data[
                "decision"
            ],
        )

        print(
            "Confidence:",
            data[
                "confidence"
            ],
        )

        print(
            "Severity:",
            data[
                "severity"
            ],
        )

        print(
            "Weighted Score:",
            data[
                "weighted_score"
            ],
        )

        print(
            "Reason:",
            data[
                "reason"
            ],
        )


    # ============================================================
    # MANUAL DECISION VALIDATION
    # ============================================================

    manual_decision = (

        AgentDecision(

            agent=
                "ResponseAgent",

            decision=
                "RESPONSE_REVIEW",

            confidence=
                85,

            severity=
                "HIGH",

            reason=
                "Security response review is recommended.",

            evidence=[
                {

                    "source":
                        "synthetic_test",
                }
            ],
        )
    )


    manual_pass = (

        manual_decision.decision
        == "RESPONSE_REVIEW"

        and manual_decision.confidence
        == 85

        and manual_decision.severity
        == "HIGH"
    )


    # ============================================================
    # TRIAGE VALIDATION
    # ============================================================

    triage_pass = (

        triage_decision.decision
        == "INVESTIGATE"

        and triage_decision.confidence
        == 95

        and triage_decision.severity
        == "CRITICAL"
    )


    # ============================================================
    # INVESTIGATION VALIDATION
    # ============================================================

    investigation_pass = (

        investigation_decision.decision
        == "RESPONSE_REVIEW"

        and investigation_decision.severity
        == "CRITICAL"
    )


    # ============================================================
    # RISK VALIDATION
    # ============================================================

    risk_pass = (

        risk_decision.decision
        == "CONTAINMENT_RECOMMENDED"

        and risk_decision.confidence
        == 96

        and risk_decision.severity
        == "CRITICAL"
    )


    # ============================================================
    # CONFIDENCE CLAMP TEST
    # ============================================================

    clamp_decision = (

        AgentDecision(

            agent=
                "TestAgent",

            decision=
                "MONITOR",

            confidence=
                150,

            severity=
                "LOW",

            reason=
                "Testing confidence bounds.",
        )
    )


    clamp_pass = (
        clamp_decision.confidence
        == 100
    )


    # ============================================================
    # INVALID DECISION TEST
    # ============================================================

    invalid_pass = False


    try:

        AgentDecision(

            agent=
                "InvalidAgent",

            decision=
                "DELETE_EVERYTHING",

            confidence=
                50,

            severity=
                "HIGH",

            reason=
                "Invalid decision test.",
        )


    except ValueError:

        invalid_pass = True


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL AGENT DECISION VALIDATION"
    )
    print("=" * 80)


    print(
        "Manual decision model:",
        "PASS"
        if manual_pass
        else "FAIL",
    )


    print(
        "Triage decision conversion:",
        "PASS"
        if triage_pass
        else "FAIL",
    )


    print(
        "Investigation decision conversion:",
        "PASS"
        if investigation_pass
        else "FAIL",
    )


    print(
        "Risk decision conversion:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Confidence validation:",
        "PASS"
        if clamp_pass
        else "FAIL",
    )


    print(
        "Invalid decision rejection:",
        "PASS"
        if invalid_pass
        else "FAIL",
    )


    overall = all(
        [

            manual_pass,

            triage_pass,

            investigation_pass,

            risk_pass,

            clamp_pass,

            invalid_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print("=" * 80)


if __name__ == "__main__":

    main()