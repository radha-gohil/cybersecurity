from agents.agent_decision import (
    AgentDecision,
)


class DecisionFactory:

    # ============================================================
    # TRIAGE DECISION
    # ============================================================

    @staticmethod
    def from_triage(
        triage: dict,
    ) -> AgentDecision:

        priority = (
            triage.get(
                "priority",
                "P4",
            )
        )


        triage_score = int(
            triage.get(
                "triage_score",
                0,
            )
            or 0
        )


        requires_investigation = (
            triage.get(
                "requires_investigation",
                False,
            )
        )


        if requires_investigation:

            decision = (
                "INVESTIGATE"
            )

        else:

            decision = (
                "MONITOR"
            )


        severity_mapping = {

            "P1":
                "CRITICAL",

            "P2":
                "HIGH",

            "P3":
                "MEDIUM",

            "P4":
                "LOW",
        }


        reasons = (
            triage.get(
                "reasons"
            )
            or []
        )


        reason = (
            "; ".join(
                str(
                    item
                )
                for item in reasons
            )
            if reasons
            else
            f"Triage priority is {priority}."
        )


        return AgentDecision(

            agent=
                "TriageAgent",

            decision=
                decision,

            confidence=
                triage_score,

            severity=
                severity_mapping.get(
                    priority,
                    "INFO",
                ),

            reason=
                reason,

            evidence=[
                {

                    "priority":
                        priority,

                    "triage_score":
                        triage_score,

                    "categories":
                        triage.get(
                            "categories",
                            [],
                        ),

                    "malware_probability":
                        triage.get(
                            "malware_probability",
                            0,
                        ),
                }
            ],
        )


    # ============================================================
    # INVESTIGATION DECISION
    # ============================================================

    @staticmethod
    def from_investigation(
        investigation: dict,
    ) -> AgentDecision:

        priority = str(
            investigation.get(
                "priority",
                "LOW",
            )
        ).upper()


        requires_response = (
            investigation.get(
                "requires_response",
                False,
            )
        )


        if requires_response:

            decision = (
                "RESPONSE_REVIEW"
            )

        else:

            decision = (
                "CONTINUE_ANALYSIS"
            )


        confidence_mapping = {

            "IMMEDIATE":
                90,

            "HIGH":
                80,

            "NORMAL":
                60,

            "LOW":
                40,
        }


        severity_mapping = {

            "IMMEDIATE":
                "CRITICAL",

            "HIGH":
                "HIGH",

            "NORMAL":
                "MEDIUM",

            "LOW":
                "LOW",
        }


        findings = (
            investigation.get(
                "findings"
            )
            or []
        )


        reason = (
            "; ".join(
                str(
                    item
                )
                for item in findings
            )
            if findings
            else
            "Investigation completed."
        )


        return AgentDecision(

            agent=
                "InvestigationAgent",

            decision=
                decision,

            confidence=
                confidence_mapping.get(
                    priority,
                    50,
                ),

            severity=
                severity_mapping.get(
                    priority,
                    "INFO",
                ),

            reason=
                reason,

            evidence=[
                {

                    "event_count":
                        investigation.get(
                            "event_count",
                            0,
                        ),

                    "category_counts":
                        investigation.get(
                            "category_counts",
                            {},
                        ),

                    "indicators":
                        investigation.get(
                            "indicators",
                            [],
                        ),
                }
            ],
        )


    # ============================================================
    # RISK DECISION
    # ============================================================

    @staticmethod
    def from_risk(
        risk: dict,
    ) -> AgentDecision:

        risk_score = int(
            risk.get(
                "risk_score",
                0,
            )
            or 0
        )


        risk_level = str(
            risk.get(
                "risk_level",
                "INFO",
            )
        ).upper()


        requires_response = (
            risk.get(
                "requires_response",
                False,
            )
        )


        if (
            requires_response
            and risk_level
            == "CRITICAL"
        ):

            decision = (
                "CONTAINMENT_RECOMMENDED"
            )


        elif requires_response:

            decision = (
                "RESPONSE_RECOMMENDED"
            )


        elif risk_score >= 35:

            decision = (
                "INVESTIGATE"
            )


        else:

            decision = (
                "MONITOR"
            )


        reasons = (
            risk.get(
                "reasons"
            )
            or []
        )


        reason = (
            "; ".join(
                str(
                    item
                )
                for item in reasons
            )
            if reasons
            else
            f"Risk level is {risk_level}."
        )


        return AgentDecision(

            agent=
                "RiskAssessmentAgent",

            decision=
                decision,

            confidence=
                risk_score,

            severity=
                risk_level,

            reason=
                reason,

            evidence=[
                {

                    "risk_score":
                        risk_score,

                    "risk_level":
                        risk_level,

                    "components":
                        risk.get(
                            "components",
                            {},
                        ),
                }
            ],

            metadata={

                "recommended_action":
                    risk.get(
                        "recommended_action"
                    ),
            },
        )