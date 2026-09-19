from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


# ================================================================
# STANDARD DECISION TYPES
# ================================================================

VALID_DECISIONS = {

    "MONITOR",

    "CONTINUE_ANALYSIS",

    "INVESTIGATE",

    "RESPONSE_REVIEW",

    "RESPONSE_RECOMMENDED",

    "CONTAINMENT_RECOMMENDED",
}


# ================================================================
# STANDARD SEVERITY LEVELS
# ================================================================

VALID_SEVERITIES = {

    "INFO",

    "LOW",

    "MEDIUM",

    "HIGH",

    "CRITICAL",
}


# ================================================================
# AGENT DECISION MODEL
# ================================================================

@dataclass
class AgentDecision:

    agent: str

    decision: str

    confidence: int

    reason: str

    severity: str = "INFO"

    evidence: List[Dict[str, Any]] = field(
        default_factory=list
    )

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    timestamp: str = field(
        default_factory=lambda:
            datetime.now(
                timezone.utc
            ).isoformat()
    )


    # ============================================================
    # POST INITIALIZATION VALIDATION
    # ============================================================

    def __post_init__(
        self,
    ):

        self.agent = str(
            self.agent
            or "UnknownAgent"
        )


        self.decision = str(
            self.decision
            or "MONITOR"
        ).upper()


        self.severity = str(
            self.severity
            or "INFO"
        ).upper()


        # --------------------------------------------------------
        # VALIDATE DECISION
        # --------------------------------------------------------

        if self.decision not in VALID_DECISIONS:

            raise ValueError(
                f"Invalid decision type: "
                f"{self.decision}"
            )


        # --------------------------------------------------------
        # VALIDATE SEVERITY
        # --------------------------------------------------------

        if self.severity not in VALID_SEVERITIES:

            raise ValueError(
                f"Invalid severity: "
                f"{self.severity}"
            )


        # --------------------------------------------------------
        # NORMALIZE CONFIDENCE
        # --------------------------------------------------------

        try:

            self.confidence = int(
                self.confidence
            )

        except (
            TypeError,
            ValueError,
        ):

            self.confidence = 0


        self.confidence = max(
            0,
            min(
                self.confidence,
                100,
            ),
        )


        # --------------------------------------------------------
        # REASON
        # --------------------------------------------------------

        self.reason = str(
            self.reason
            or "No reason provided."
        )


        # --------------------------------------------------------
        # EVIDENCE
        # --------------------------------------------------------

        if not isinstance(
            self.evidence,
            list,
        ):

            self.evidence = []


        # --------------------------------------------------------
        # METADATA
        # --------------------------------------------------------

        if not isinstance(
            self.metadata,
            dict,
        ):

            self.metadata = {}


    # ============================================================
    # DECISION PRIORITY
    # ============================================================

    def decision_priority(
        self,
    ) -> int:

        mapping = {

            "MONITOR":
                1,

            "CONTINUE_ANALYSIS":
                2,

            "INVESTIGATE":
                3,

            "RESPONSE_REVIEW":
                4,

            "RESPONSE_RECOMMENDED":
                5,

            "CONTAINMENT_RECOMMENDED":
                6,
        }


        return mapping.get(
            self.decision,
            0,
        )


    # ============================================================
    # SEVERITY PRIORITY
    # ============================================================

    def severity_priority(
        self,
    ) -> int:

        mapping = {

            "INFO":
                1,

            "LOW":
                2,

            "MEDIUM":
                3,

            "HIGH":
                4,

            "CRITICAL":
                5,
        }


        return mapping.get(
            self.severity,
            1,
        )


    # ============================================================
    # WEIGHTED DECISION SCORE
    # ============================================================

    def weighted_score(
        self,
    ) -> float:

        decision_weight = (
            self.decision_priority()
            * 10
        )


        severity_weight = (
            self.severity_priority()
            * 5
        )


        confidence_weight = (
            self.confidence
            * 0.5
        )


        score = (

            decision_weight
            + severity_weight
            + confidence_weight
        )


        return round(
            score,
            2,
        )


    # ============================================================
    # CONVERT TO DICT
    # ============================================================

    def to_dict(
        self,
    ) -> dict:

        return {

            "agent":
                self.agent,

            "decision":
                self.decision,

            "confidence":
                self.confidence,

            "severity":
                self.severity,

            "reason":
                self.reason,

            "evidence":
                self.evidence,

            "metadata":
                self.metadata,

            "timestamp":
                self.timestamp,

            "decision_priority":
                self.decision_priority(),

            "severity_priority":
                self.severity_priority(),

            "weighted_score":
                self.weighted_score(),
        }