from agents.shared_context import (
    SharedIncidentContext,
)


def main():

    print()
    print("=" * 75)
    print(
        "SENTINEL-X SHARED AGENT CONTEXT TEST"
    )
    print("=" * 75)


    incident = {

        "incident_id":
            "INC-CONTEXT-001",

        "severity":
            "CRITICAL",

        "correlation_score":
            90,
    }


    context = (
        SharedIncidentContext(
            incident
        )
    )


    # ============================================================
    # TRIAGE AGENT OUTPUT
    # ============================================================

    context.set_agent_output(

        "TriageAgent",

        {

            "priority":
                "P1",

            "triage_score":
                95,
        },
    )


    # ============================================================
    # INVESTIGATION OUTPUT
    # ============================================================

    context.set_agent_output(

        "InvestigationAgent",

        {

            "priority":
                "IMMEDIATE",

            "finding_count":
                5,
        },
    )


    # ============================================================
    # EVIDENCE
    # ============================================================

    context.set_evidence(
        {

            "processes": [
                {
                    "pid":
                        5000,

                    "name":
                        "demo.exe",
                }
            ],

            "files": [
                {
                    "path":
                        r"C:\Temp\demo.exe",
                }
            ],
        }
    )


    # ============================================================
    # RISK
    # ============================================================

    context.set_risk(
        {

            "risk_score":
                92,

            "risk_level":
                "CRITICAL",
        }
    )


    # ============================================================
    # RECOMMENDATION
    # ============================================================

    context.add_recommendation(

        "RiskAssessmentAgent",

        "Immediate containment review recommended.",

        priority="HIGH",
    )


    # ============================================================
    # DECISION
    # ============================================================

    context.add_decision(

        "TriageAgent",

        "INVESTIGATE",

        confidence=95,

        reason=
            "Critical multi-source incident.",
    )


    result = (
        context.to_dict()
    )


    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )


    print(
        "Agent Outputs:",
        list(
            result[
                "agent_outputs"
            ].keys()
        ),
    )


    print(
        "Risk:",
        result[
            "risk"
        ],
    )


    print(
        "Recommendations:",
        result[
            "recommendations"
        ],
    )


    print(
        "Decisions:",
        result[
            "decisions"
        ],
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    incident_pass = (
        result[
            "incident_id"
        ]
        == "INC-CONTEXT-001"
    )


    triage_pass = (
        result[
            "agent_outputs"
        ][
            "TriageAgent"
        ][
            "priority"
        ]
        == "P1"
    )


    investigation_pass = (
        "InvestigationAgent"
        in result[
            "agent_outputs"
        ]
    )


    evidence_pass = (
        len(
            result[
                "evidence"
            ][
                "processes"
            ]
        )
        == 1
    )


    risk_pass = (
        result[
            "risk"
        ][
            "risk_level"
        ]
        == "CRITICAL"
    )


    recommendation_pass = (
        len(
            result[
                "recommendations"
            ]
        )
        == 1
    )


    decision_pass = (
        len(
            result[
                "decisions"
            ]
        )
        == 1
    )


    print()
    print("=" * 75)
    print(
        "FINAL SHARED CONTEXT VALIDATION"
    )
    print("=" * 75)


    print(
        "Incident storage:",
        "PASS"
        if incident_pass
        else "FAIL",
    )


    print(
        "Triage agent output:",
        "PASS"
        if triage_pass
        else "FAIL",
    )


    print(
        "Investigation output:",
        "PASS"
        if investigation_pass
        else "FAIL",
    )


    print(
        "Evidence sharing:",
        "PASS"
        if evidence_pass
        else "FAIL",
    )


    print(
        "Risk sharing:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Recommendation sharing:",
        "PASS"
        if recommendation_pass
        else "FAIL",
    )


    print(
        "Decision sharing:",
        "PASS"
        if decision_pass
        else "FAIL",
    )


    overall = all(
        [
            incident_pass,
            triage_pass,
            investigation_pass,
            evidence_pass,
            risk_pass,
            recommendation_pass,
            decision_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )


    print("=" * 75)


if __name__ == "__main__":

    main()