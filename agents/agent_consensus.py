from collections import defaultdict
from datetime import datetime, timezone

from agents.agent_decision import AgentDecision


class AgentConsensusEngine:

    def __init__(self, minimum_support: int = 1):

        self.name = "AgentConsensusEngine"
        self.minimum_support = minimum_support


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self) -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # DECISION PRIORITY
    # ============================================================

    def decision_priority(self, decision: str) -> int:

        mapping = {
            "MONITOR": 1,
            "CONTINUE_ANALYSIS": 2,
            "INVESTIGATE": 3,
            "RESPONSE_REVIEW": 4,
            "RESPONSE_RECOMMENDED": 5,
            "CONTAINMENT_RECOMMENDED": 6,
        }

        return mapping.get(
            str(decision).upper(),
            0,
        )


    # ============================================================
    # SEVERITY PRIORITY
    # ============================================================

    def severity_priority(self, severity: str) -> int:

        mapping = {
            "INFO": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
        }

        return mapping.get(
            str(severity).upper(),
            1,
        )


    # ============================================================
    # NORMALIZE DECISION
    # ============================================================

    def normalize_decision(self, decision) -> dict:

        if isinstance(
            decision,
            AgentDecision,
        ):

            return decision.to_dict()

        if isinstance(
            decision,
            dict,
        ):

            return dict(decision)

        raise TypeError(
            "Decision must be AgentDecision or dict."
        )


    # ============================================================
    # CALCULATE VOTE WEIGHT
    # ============================================================

    def calculate_vote_weight(
        self,
        decision: dict,
    ) -> float:

        confidence = decision.get(
            "confidence",
            0,
        )

        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        confidence = max(
            0.0,
            min(
                confidence,
                100.0,
            ),
        )

        decision_priority = self.decision_priority(
            decision.get(
                "decision"
            )
        )

        severity_priority = self.severity_priority(
            decision.get(
                "severity"
            )
        )

        weight = (
            confidence * 0.60
            + decision_priority * 5
            + severity_priority * 2
        )

        return round(
            weight,
            2,
        )


    # ============================================================
    # GROUP DECISIONS
    # ============================================================

    def group_decisions(
        self,
        decisions: list,
    ) -> dict:

        grouped = defaultdict(list)

        for decision in decisions:

            normalized = self.normalize_decision(
                decision
            )

            decision_name = str(
                normalized.get(
                    "decision",
                    "MONITOR",
                )
            ).upper()

            grouped[
                decision_name
            ].append(
                normalized
            )

        return dict(grouped)


    # ============================================================
    # SCORE GROUPS
    # ============================================================

    def score_groups(
        self,
        grouped: dict,
    ) -> dict:

        scores = {}

        for decision_name, items in grouped.items():

            total_weight = 0.0

            for item in items:

                total_weight += (
                    self.calculate_vote_weight(
                        item
                    )
                )

            scores[
                decision_name
            ] = {
                "support": len(items),

                "total_weight": round(
                    total_weight,
                    2,
                ),

                "average_weight": round(
                    (
                        total_weight / len(items)
                    )
                    if items
                    else 0.0,
                    2,
                ),

                "agents": [
                    item.get("agent")
                    for item in items
                ],
            }

        return scores


    # ============================================================
    # SELECT FINAL DECISION
    # ============================================================

    def select_final_decision(
        self,
        scores: dict,
    ) -> str:

        if not scores:
            return "MONITOR"

        candidates = []

        for decision_name, data in scores.items():

            support = data.get(
                "support",
                0,
            )

            if support < self.minimum_support:
                continue

            candidates.append(
                (
                    decision_name,
                    data.get(
                        "total_weight",
                        0,
                    ),
                    self.decision_priority(
                        decision_name
                    ),
                )
            )

        if not candidates:
            return "MONITOR"

        candidates.sort(
            key=lambda item: (
                item[1],
                item[2],
            ),
            reverse=True,
        )

        return candidates[0][0]


    # ============================================================
    # MAX SEVERITY
    # ============================================================

    def get_max_severity(
        self,
        decisions: list,
    ) -> str:

        severity_mapping = {
            "INFO": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
        }

        maximum = "INFO"
        maximum_score = 1

        for decision in decisions:

            normalized = self.normalize_decision(
                decision
            )

            severity = str(
                normalized.get(
                    "severity",
                    "INFO",
                )
            ).upper()

            score = severity_mapping.get(
                severity,
                1,
            )

            if score > maximum_score:

                maximum = severity
                maximum_score = score

        return maximum


    # ============================================================
    # AVERAGE CONFIDENCE
    # ============================================================

    def average_confidence(
        self,
        decisions: list,
    ) -> int:

        values = []

        for decision in decisions:

            normalized = self.normalize_decision(
                decision
            )

            try:
                value = int(
                    normalized.get(
                        "confidence",
                        0,
                    )
                )
            except (TypeError, ValueError):
                value = 0

            values.append(
                max(
                    0,
                    min(
                        value,
                        100,
                    ),
                )
            )

        if not values:
            return 0

        return round(
            sum(values) / len(values)
        )


    # ============================================================
    # BUILD EXPLANATION
    # ============================================================

    def build_explanation(
        self,
        final_decision: str,
        decisions: list,
        scores: dict,
    ) -> list:

        explanation = []

        explanation.append(
            f"Consensus decision selected: "
            f"{final_decision}."
        )

        selected = scores.get(
            final_decision,
            {},
        )

        support = selected.get(
            "support",
            0,
        )

        agents = selected.get(
            "agents",
            [],
        )

        explanation.append(
            f"{support} agent(s) directly supported "
            f"this decision."
        )

        if agents:

            explanation.append(
                "Supporting agents: "
                + ", ".join(
                    str(agent)
                    for agent in agents
                )
            )

        for decision in decisions:

            normalized = self.normalize_decision(
                decision
            )

            explanation.append(
                f"{normalized.get('agent')} -> "
                f"{normalized.get('decision')} "
                f"(confidence "
                f"{normalized.get('confidence')}%, "
                f"severity "
                f"{normalized.get('severity')})."
            )

        return explanation


    # ============================================================
    # CONFLICT DETECTION
    # ============================================================

    def detect_conflict(
        self,
        decisions: list,
    ) -> bool:

        unique_decisions = set()

        for decision in decisions:

            normalized = self.normalize_decision(
                decision
            )

            unique_decisions.add(
                str(
                    normalized.get(
                        "decision"
                    )
                ).upper()
            )

        return len(
            unique_decisions
        ) > 1


    # ============================================================
    # REACH CONSENSUS
    # ============================================================

    def reach_consensus(
        self,
        decisions: list,
    ) -> dict:

        if not decisions:

            return {
                "engine": self.name,

                "generated_at":
                    self.now_iso(),

                "final_decision":
                    "MONITOR",

                "consensus_confidence":
                    0,

                "severity":
                    "INFO",

                "agent_count":
                    0,

                "conflict_detected":
                    False,

                "vote_summary":
                    {},

                "explanation": [
                    "No agent decisions were provided."
                ],
            }

        grouped = self.group_decisions(
            decisions
        )

        scores = self.score_groups(
            grouped
        )

        final_decision = self.select_final_decision(
            scores
        )

        confidence = self.average_confidence(
            decisions
        )

        severity = self.get_max_severity(
            decisions
        )

        conflict = self.detect_conflict(
            decisions
        )

        explanation = self.build_explanation(
            final_decision,
            decisions,
            scores,
        )

        return {
            "engine":
                self.name,

            "generated_at":
                self.now_iso(),

            "final_decision":
                final_decision,

            "consensus_confidence":
                confidence,

            "severity":
                severity,

            "agent_count":
                len(decisions),

            "conflict_detected":
                conflict,

            "vote_summary":
                scores,

            "explanation":
                explanation,
        }