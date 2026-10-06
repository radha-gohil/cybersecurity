from copy import deepcopy

from response.endpoint_digital_twin import EndpointDigitalTwin
from response.digital_twin_response_planner import DigitalTwinResponsePlanner


class DigitalTwinDecisionIntegration:

    def __init__(self):

        self.name = "DigitalTwinDecisionIntegration"

        self.planner = DigitalTwinResponsePlanner()


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_list(self, value):

        if isinstance(value, list):
            return value

        return []


    def safe_dict(self, value):

        if isinstance(value, dict):
            return value

        return {}


    # ============================================================
    # BUILD TWIN FROM INTELLIGENCE OUTPUT
    # ============================================================

    def build_twin(
        self,
        incident_id,
        intelligence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )


        risk = self.safe_dict(
            intelligence.get(
                "risk"
            )
        )


        coordinated = self.safe_dict(
            intelligence.get(
                "coordinated_analysis"
            )
        )


        evidence = self.safe_dict(
            coordinated.get(
                "evidence"
            )
        )


        # ========================================================
        # FALLBACK:
        # Some pipeline versions may store evidence inside context
        # ========================================================

        if not evidence:

            context = self.safe_dict(
                coordinated.get(
                    "context"
                )
            )


            evidence = self.safe_dict(
                context.get(
                    "evidence"
                )
            )


        initial_risk_score = risk.get(
            "risk_score",
            intelligence.get(
                "risk_score",
                0,
            ),
        )


        initial_risk_level = risk.get(
            "risk_level",
            intelligence.get(
                "risk_level",
                "INFO",
            ),
        )


        twin = EndpointDigitalTwin(

            incident_id=incident_id,

            initial_risk_score=
                initial_risk_score,

            initial_risk_level=
                initial_risk_level,
        )


        twin.load_evidence(
            evidence
        )


        return twin


    # ============================================================
    # EXTRACT RECOMMENDATIONS
    # ============================================================

    def extract_recommendations(
        self,
        intelligence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )


        response = self.safe_dict(
            intelligence.get(
                "response"
            )
        )


        recommendations = response.get(
            "recommendations",
            [],
        )


        return self.safe_list(
            recommendations
        )


    # ============================================================
    # TARGET NORMALIZATION
    # ============================================================

    def safe_int(
        self,
        value,
        default=None,
    ):

        try:
            if value is None or isinstance(value, bool):
                return default

            return int(
                value
            )

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):
            return default


    def normalize_process_target(
        self,
        target,
        twin,
    ):

        target = self.safe_dict(
            target
        )

        raw_items = target.get(
            "processes"
        )

        if not isinstance(
            raw_items,
            list,
        ):
            raw_items = (
                [target]
                if target
                else []
            )


        by_pid = {}


        for item in raw_items:

            if not isinstance(
                item,
                dict,
            ):
                continue


            pid = self.safe_int(
                item.get(
                    "pid"
                )
            )


            if (
                pid is None
                or pid <= 0
            ):
                continue


            # Keep only entities that actually exist in the
            # virtual endpoint state.
            if twin.find_process(
                pid
            ) is None:
                continue


            candidate = deepcopy(
                item
            )

            candidate[
                "pid"
            ] = pid


            existing = by_pid.get(
                pid
            )


            if existing is None:

                by_pid[
                    pid
                ] = candidate

                continue


            # Prefer the target carrying a semantic threat type.
            existing_has_type = bool(
                existing.get(
                    "threat_type"
                )
            )

            candidate_has_type = bool(
                candidate.get(
                    "threat_type"
                )
            )


            if (
                candidate_has_type
                and not existing_has_type
            ):

                by_pid[
                    pid
                ] = candidate

                continue


            # If both have the same semantic quality, retain the
            # stronger explicitly supplied threat score.
            if (
                candidate_has_type
                == existing_has_type
            ):

                existing_score = (
                    self.safe_int(
                        existing.get(
                            "threat_score"
                        ),
                        0,
                    )
                    or 0
                )

                candidate_score = (
                    self.safe_int(
                        candidate.get(
                            "threat_score"
                        ),
                        0,
                    )
                    or 0
                )


                if (
                    candidate_score
                    > existing_score
                ):

                    by_pid[
                        pid
                    ] = candidate


        processes = list(
            by_pid.values()
        )


        # Fallback to the first known twin process if the
        # recommendation did not provide a usable target.
        if (
            not processes
            and twin.processes
        ):

            process = self.safe_dict(
                twin.processes[
                    0
                ]
            )

            pid = self.safe_int(
                process.get(
                    "pid"
                )
            )


            if (
                pid is not None
                and pid > 0
            ):

                processes.append(
                    {
                        "pid":
                            pid,

                        "name":
                            process.get(
                                "name"
                            ),

                        "exe":
                            process.get(
                                "exe"
                            ),

                        "threat_score":
                            (
                                process.get(
                                    "combined_threat_score"
                                )
                                or process.get(
                                    "behavior_score"
                                )
                                or process.get(
                                    "anomaly_score"
                                )
                                or 0
                            ),

                        "threat_type":
                            process.get(
                                "threat_type"
                            ),
                    }
                )


        return {
            "processes":
                processes
        }


    def normalize_file_target(
        self,
        target,
        twin,
    ):

        target = self.safe_dict(
            target
        )

        raw_items = target.get(
            "files"
        )

        if not isinstance(
            raw_items,
            list,
        ):
            raw_items = (
                [target]
                if target
                else []
            )


        files = []

        seen = set()


        for item in raw_items:

            if not isinstance(
                item,
                dict,
            ):
                continue


            path = item.get(
                "path"
            )

            sha256 = item.get(
                "sha256"
            )


            if twin.find_file(
                path=path,
                sha256=sha256,
            ) is None:
                continue


            signature = (
                str(
                    path
                    or ""
                ).lower(),

                str(
                    sha256
                    or ""
                ).lower(),
            )


            if signature in seen:
                continue


            seen.add(
                signature
            )

            files.append(
                deepcopy(
                    item
                )
            )


        if (
            not files
            and twin.files
        ):

            item = self.safe_dict(
                twin.files[
                    0
                ]
            )

            files.append(
                {
                    "path":
                        item.get(
                            "path"
                        ),

                    "sha256":
                        item.get(
                            "sha256"
                        ),
                }
            )


        return {
            "files":
                files
        }


    def normalize_network_target(
        self,
        target,
        twin,
    ):

        target = self.safe_dict(
            target
        )

        raw_items = target.get(
            "connections"
        )

        if not isinstance(
            raw_items,
            list,
        ):
            raw_items = (
                [target]
                if target
                else []
            )


        connections = []

        seen = set()


        for item in raw_items:

            if not isinstance(
                item,
                dict,
            ):
                continue


            remote_ip = item.get(
                "remote_ip"
            )

            remote_port = item.get(
                "remote_port"
            )


            if not remote_ip:
                continue


            if twin.find_network_connection(
                remote_ip,
                remote_port,
            ) is None:
                continue


            signature = (
                str(
                    remote_ip
                ),

                str(
                    remote_port
                ),
            )


            if signature in seen:
                continue


            seen.add(
                signature
            )

            connections.append(
                deepcopy(
                    item
                )
            )


        if (
            not connections
            and twin.network_connections
        ):

            item = self.safe_dict(
                twin.network_connections[
                    0
                ]
            )

            connections.append(
                {
                    "remote_ip":
                        item.get(
                            "remote_ip"
                        ),

                    "remote_port":
                        item.get(
                            "remote_port"
                        ),

                    "pid":
                        item.get(
                            "pid"
                        ),

                    "process_name":
                        item.get(
                            "process_name"
                        ),
                }
            )


        return {
            "connections":
                connections
        }


    def normalize_registry_target(
        self,
        target,
        twin,
    ):

        target = self.safe_dict(
            target
        )

        raw_items = target.get(
            "registry_artifacts"
        )

        if not isinstance(
            raw_items,
            list,
        ):
            raw_items = (
                [target]
                if target
                else []
            )


        artifacts = []

        seen = set()


        for item in raw_items:

            if not isinstance(
                item,
                dict,
            ):
                continue


            key = item.get(
                "key"
            )

            value_name = item.get(
                "value_name"
            )


            if not key:
                continue


            if twin.find_persistence_artifact(
                key,
                value_name,
            ) is None:
                continue


            signature = (
                str(
                    key
                ).lower(),

                str(
                    value_name
                    or ""
                ).lower(),
            )


            if signature in seen:
                continue


            seen.add(
                signature
            )

            artifacts.append(
                deepcopy(
                    item
                )
            )


        if (
            not artifacts
            and twin.persistence_artifacts
        ):

            item = self.safe_dict(
                twin.persistence_artifacts[
                    0
                ]
            )

            artifacts.append(
                {
                    "key":
                        item.get(
                            "key"
                        ),

                    "value_name":
                        item.get(
                            "value_name"
                        ),

                    "value_data":
                        item.get(
                            "value_data"
                        ),
                }
            )


        return {
            "registry_artifacts":
                artifacts
        }


    # ============================================================
    # RECOMMENDATION -> DIGITAL TWIN ACTION
    # ============================================================

    def recommendation_to_action(
        self,
        recommendation,
        twin,
    ):

        recommendation = self.safe_dict(
            recommendation
        )


        rec_type = str(

            recommendation.get(
                "recommendation_type",

                recommendation.get(
                    "action",
                    "",
                ),
            )

        ).upper()


        target = self.safe_dict(
            recommendation.get(
                "target"
            )
        )


        # ========================================================
        # QUARANTINE
        # ========================================================

        if rec_type in {
            "QUARANTINE_REVIEW",
            "QUARANTINE_FILE",
        }:

            normalized = (
                self.normalize_file_target(
                    target,
                    twin,
                )
            )


            if normalized[
                "files"
            ]:

                return {
                    "action_type":
                        "QUARANTINE_FILE",

                    "target":
                        normalized,
                }


        # ========================================================
        # PROCESS
        # ========================================================

        if rec_type in {
            "PROCESS_TERMINATION_REVIEW",
            "TERMINATE_PROCESS",
        }:

            normalized = (
                self.normalize_process_target(
                    target,
                    twin,
                )
            )


            if normalized[
                "processes"
            ]:

                return {
                    "action_type":
                        "TERMINATE_PROCESS",

                    "target":
                        normalized,
                }


        # ========================================================
        # NETWORK
        # ========================================================

        if rec_type in {
            "NETWORK_BLOCK_REVIEW",
            "BLOCK_NETWORK",
        }:

            normalized = (
                self.normalize_network_target(
                    target,
                    twin,
                )
            )


            if normalized[
                "connections"
            ]:

                return {
                    "action_type":
                        "BLOCK_NETWORK",

                    "target":
                        normalized,
                }


        # ========================================================
        # PERSISTENCE
        # ========================================================

        if rec_type in {
            "PERSISTENCE_REMEDIATION_REVIEW",
            "REMEDIATE_PERSISTENCE",
        }:

            normalized = (
                self.normalize_registry_target(
                    target,
                    twin,
                )
            )


            if normalized[
                "registry_artifacts"
            ]:

                return {
                    "action_type":
                        "REMEDIATE_PERSISTENCE",

                    "target":
                        normalized,
                }


        # ========================================================
        # ENDPOINT ISOLATION
        # ========================================================

        if rec_type in {
            "ENDPOINT_ISOLATION_REVIEW",
            "ISOLATE_ENDPOINT",
        }:

            return {
                "action_type":
                    "ISOLATE_ENDPOINT",

                "target":
                    deepcopy(
                        target
                    ),
            }


        return None


    # ============================================================
    # BUILD CANDIDATE ACTIONS
    # ============================================================

    def build_candidate_actions(
        self,
        intelligence,
        twin,
    ):

        recommendations = (
            self.extract_recommendations(
                intelligence
            )
        )


        actions = []


        for recommendation in recommendations:

            action = (
                self.recommendation_to_action(

                    recommendation=
                        recommendation,

                    twin=
                        twin,
                )
            )


            if action is not None:

                actions.append(
                    action
                )


        # ========================================================
        # REMOVE DUPLICATE ACTION TYPES
        # ========================================================

        unique_actions = []

        seen = set()


        for action in actions:

            action_type = action.get(
                "action_type"
            )


            if action_type in seen:
                continue


            seen.add(
                action_type
            )


            unique_actions.append(
                action
            )


        return unique_actions


    # ============================================================
    # BUILD RESPONSE PLANS
    # ============================================================

    def build_response_plans(
        self,
        candidate_actions,
    ):

        candidate_actions = self.safe_list(
            candidate_actions
        )


        plans = []


        # ========================================================
        # PLAN 1
        # MINIMAL TARGETED RESPONSE
        # ========================================================

        if candidate_actions:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-1",

                    "plan_name":
                        "Minimal Targeted Response",

                    "description":
                        (
                            "Apply the first targeted response "
                            "recommended by the intelligence layer."
                        ),

                    "actions": [
                        deepcopy(
                            candidate_actions[0]
                        )
                    ],
                }
            )


        # ========================================================
        # PLAN 2
        # TARGETED CONTAINMENT
        # ========================================================

        if len(
            candidate_actions
        ) >= 2:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-2",

                    "plan_name":
                        "Targeted Containment",

                    "description":
                        (
                            "Apply two complementary "
                            "response actions."
                        ),

                    "actions":
                        deepcopy(
                            candidate_actions[:2]
                        ),
                }
            )


        # ========================================================
        # PLAN 3
        # ALL TARGETED REMEDIATION WITHOUT ISOLATION
        # ========================================================

        non_isolation_actions = [

            deepcopy(
                action
            )

            for action in candidate_actions

            if action.get(
                "action_type"
            )
            != "ISOLATE_ENDPOINT"
        ]


        if non_isolation_actions:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-3",

                    "plan_name":
                        "Targeted Full Remediation",

                    "description":
                        (
                            "Apply all targeted remediation "
                            "actions without endpoint isolation."
                        ),

                    "actions":
                        non_isolation_actions,
                }
            )


        # ========================================================
        # PLAN 4
        # FULL CONTAINMENT
        # ========================================================

        isolation_present = any(

            action.get(
                "action_type"
            )
            == "ISOLATE_ENDPOINT"

            for action in candidate_actions
        )


        if isolation_present:

            plans.append(
                {
                    "plan_id":
                        "DT-PLAN-4",

                    "plan_name":
                        "Full Endpoint Containment",

                    "description":
                        (
                            "Apply all recommended controls "
                            "including endpoint isolation."
                        ),

                    "actions":
                        deepcopy(
                            candidate_actions
                        ),
                }
            )


        # ========================================================
        # REMOVE DUPLICATE PLANS
        # ========================================================

        final_plans = []

        seen_signatures = set()


        for plan in plans:

            signature = tuple(

                action.get(
                    "action_type"
                )

                for action in plan.get(
                    "actions",
                    []
                )
            )


            if signature in seen_signatures:
                continue


            seen_signatures.add(
                signature
            )


            final_plans.append(
                plan
            )


        return final_plans


    # ============================================================
    # APPROVAL DECISION
    # ============================================================

    def requires_analyst_approval(
        self,
        best_plan,
    ):

        if not best_plan:
            return False


        approval_actions = {

            "QUARANTINE_FILE",
            "TERMINATE_PROCESS",
            "BLOCK_NETWORK",
            "REMEDIATE_PERSISTENCE",
            "ISOLATE_ENDPOINT",
        }


        for action in best_plan.get(
            "actions",
            []
        ):

            if action.get(
                "action_type"
            ) in approval_actions:

                return True


        return False


    # ============================================================
    # MAIN EVALUATION
    # ============================================================

    def evaluate(
        self,
        incident_id,
        intelligence,
    ):

        twin = self.build_twin(

            incident_id=
                incident_id,

            intelligence=
                intelligence,
        )


        candidate_actions = (
            self.build_candidate_actions(

                intelligence=
                    intelligence,

                twin=
                    twin,
            )
        )


        plans = (
            self.build_response_plans(
                candidate_actions
            )
        )


        if not plans:

            return {
                "integration":
                    self.name,

                "incident_id":
                    incident_id,

                "twin_id":
                    twin.twin_id,

                "initial_risk_score":
                    twin.initial_risk_score,

                "initial_risk_level":
                    twin.initial_risk_level,

                "candidate_action_count":
                    0,

                "candidate_actions":
                    [],

                "plans_evaluated":
                    0,

                "ranked_plans":
                    [],

                "best_plan":
                    None,

                "requires_analyst_approval":
                    False,

                "decision":
                    "NO_RESPONSE_PLAN_AVAILABLE",

                "real_endpoint_modified":
                    False,
            }


        planner_result = (
            self.planner.compare_plans(

                source_twin=
                    twin,

                plans=
                    plans,
            )
        )


        best_plan = planner_result.get(
            "best_plan"
        )


        approval_required = (
            self.requires_analyst_approval(
                best_plan
            )
        )


        return {
            "integration":
                self.name,

            "incident_id":
                incident_id,

            "twin_id":
                twin.twin_id,

            "initial_risk_score":
                twin.initial_risk_score,

            "initial_risk_level":
                twin.initial_risk_level,

            "candidate_action_count":
                len(
                    candidate_actions
                ),

            "candidate_actions":
                candidate_actions,

            "plans_evaluated":
                planner_result.get(
                    "plans_evaluated",
                    0,
                ),

            "ranked_plans":
                planner_result.get(
                    "ranked_plans",
                    [],
                ),

            "best_plan":
                best_plan,

            "requires_analyst_approval":
                approval_required,

            "decision":
                (
                    "ANALYST_APPROVAL_REQUIRED"
                    if approval_required
                    else "SAFE_TO_CONTINUE"
                ),

            "real_endpoint_modified":
                False,
        }