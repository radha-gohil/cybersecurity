from copy import deepcopy
from datetime import datetime, timezone


class SharedIncidentContext:

    def __init__(
        self,
        incident: dict,
    ):

        self.incident = deepcopy(
            incident
            if isinstance(
                incident,
                dict,
            )
            else {}
        )

        self.incident_id = (
            self.incident.get(
                "incident_id"
            )
        )

        self.created_at = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        # ========================================================
        # AGENT OUTPUTS
        # ========================================================

        self.agent_outputs = {}

        # ========================================================
        # SHARED KNOWLEDGE
        # ========================================================

        self.evidence = {}

        self.attack_timeline = {}

        self.attack_graph = {}

        self.risk = {}

        self.recommendations = []

        self.decisions = []

        self.errors = []


    # ============================================================
    # STORE AGENT OUTPUT
    # ============================================================

    def set_agent_output(
        self,
        agent_name: str,
        output: dict,
    ):

        if not isinstance(
            output,
            dict,
        ):

            output = {}


        self.agent_outputs[
            agent_name
        ] = deepcopy(
            output
        )


    # ============================================================
    # GET AGENT OUTPUT
    # ============================================================

    def get_agent_output(
        self,
        agent_name: str,
    ) -> dict:

        return deepcopy(
            self.agent_outputs.get(
                agent_name,
                {}
            )
        )


    # ============================================================
    # ADD RECOMMENDATION
    # ============================================================

    def add_recommendation(
        self,
        agent_name: str,
        recommendation: str,
        priority: str = "NORMAL",
    ):

        item = {

            "agent":
                agent_name,

            "recommendation":
                recommendation,

            "priority":
                priority,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),
        }


        if item not in self.recommendations:

            self.recommendations.append(
                item
            )


    # ============================================================
    # ADD DECISION
    # ============================================================

    def add_decision(
        self,
        agent_name: str,
        decision: str,
        confidence: int = 0,
        reason: str = None,
    ):

        self.decisions.append(
            {

                "agent":
                    agent_name,

                "decision":
                    decision,

                "confidence":
                    confidence,

                "reason":
                    reason,

                "timestamp":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),
            }
        )


    # ============================================================
    # ADD ERROR
    # ============================================================

    def add_error(
        self,
        agent_name: str,
        error,
    ):

        self.errors.append(
            {

                "agent":
                    agent_name,

                "error":
                    str(
                        error
                    ),

                "timestamp":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),
            }
        )


    # ============================================================
    # UPDATE EVIDENCE
    # ============================================================

    def set_evidence(
        self,
        evidence: dict,
    ):

        self.evidence = deepcopy(
            evidence
            if isinstance(
                evidence,
                dict,
            )
            else {}
        )


    # ============================================================
    # UPDATE TIMELINE
    # ============================================================

    def set_attack_timeline(
        self,
        timeline: dict,
    ):

        self.attack_timeline = deepcopy(
            timeline
            if isinstance(
                timeline,
                dict,
            )
            else {}
        )


    # ============================================================
    # UPDATE GRAPH
    # ============================================================

    def set_attack_graph(
        self,
        graph: dict,
    ):

        self.attack_graph = deepcopy(
            graph
            if isinstance(
                graph,
                dict,
            )
            else {}
        )


    # ============================================================
    # UPDATE RISK
    # ============================================================

    def set_risk(
        self,
        risk: dict,
    ):

        self.risk = deepcopy(
            risk
            if isinstance(
                risk,
                dict,
            )
            else {}
        )


    # ============================================================
    # EXPORT COMPLETE CONTEXT
    # ============================================================

    def to_dict(
        self,
    ) -> dict:

        return {

            "incident_id":
                self.incident_id,

            "created_at":
                self.created_at,

            "incident":
                deepcopy(
                    self.incident
                ),

            "agent_outputs":
                deepcopy(
                    self.agent_outputs
                ),

            "evidence":
                deepcopy(
                    self.evidence
                ),

            "attack_timeline":
                deepcopy(
                    self.attack_timeline
                ),

            "attack_graph":
                deepcopy(
                    self.attack_graph
                ),

            "risk":
                deepcopy(
                    self.risk
                ),

            "recommendations":
                deepcopy(
                    self.recommendations
                ),

            "decisions":
                deepcopy(
                    self.decisions
                ),

            "errors":
                deepcopy(
                    self.errors
                ),
        }