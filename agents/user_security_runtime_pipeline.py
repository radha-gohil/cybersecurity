from __future__ import annotations

import logging

from datetime import (

    datetime,

    timezone,

)





from typing import (

    Any,

    Dict,

    Optional,

)





# NOTE: In Python source, remove this comment if your editor complains.

# The actual imports below are normal Python.





from agents.ai_risk_reasoning_agent import (

    shared_ai_risk_reasoning_agent,

)





from agents.ai_response_recommendation_agent import (

    shared_ai_response_recommendation_agent,

)





from agents.ai_digital_twin_plan_selection_agent import (

    shared_ai_digital_twin_plan_selection_agent,

)





from agents.protection_mode_policy import (

    shared_protection_mode_policy,

)





from agents.ai_user_explanation_agent import (

    shared_ai_user_explanation_agent,

)





from api.user_security_router import (

    publish_user_security_snapshot,

)





# ================================================================

# LOGGER

# ================================================================



logger = logging.getLogger(

    __name__

)





# ================================================================

# SENTINEL-X 7D.11

# USER SECURITY RUNTIME PIPELINE

# ================================================================





class UserSecurityRuntimePipeline:

    """

    Internal runtime bridge for the final user-facing Sentinel-X

    AI security flow.



    Flow:



        Canonical Security Threat



            ↓



        7D.2 / 7D.3 evidence context

            supplied through the 7D.4 and 7D.5 agents



            ↓



        7D.4 AI Risk Reasoning



            ↓



        7D.5 AI Response Recommendation



            ↓



        7D.6 Digital Twin + AI Plan Selection



            ↓



        7D.7 Protection Mode Policy



            ↓



        7D.8 AI User Explanation



            ↓



        7D.9 User Security Snapshot Store





    IMPORTANT:



        This class NEVER performs a real endpoint response.



        It only:



            - reasons

            - simulates

            - selects simulated plans

            - applies user policy

            - creates user explanations

            - publishes read-only frontend snapshots

    """





    VERSION = (

        "7D.11-v1"

    )





    SCHEMA_VERSION = (

        "sentinelx.ai."

        "user-security-runtime-pipeline.v1"

    )





    VALID_PLAN_STATUSES = {

        "SELECTED",

        "NOT_REQUIRED",

    }





    VALID_POLICY_DECISIONS = {

        "MONITOR",

        "ASK_USER",

        "PROTECT_PREVIEW",

    }





    # ============================================================

    # INITIALIZATION

    # ============================================================



    def __init__(

        self,



        risk_agent=None,



        response_agent=None,



        plan_selection_agent=None,



        protection_policy=None,



        explanation_agent=None,



        publisher=None,

    ):



        self.name = (

            "UserSecurityRuntimePipeline"

        )





        self.risk_agent = (

            risk_agent

            if risk_agent is not None

            else shared_ai_risk_reasoning_agent

        )





        self.response_agent = (

            response_agent

            if response_agent is not None

            else shared_ai_response_recommendation_agent

        )





        self.plan_selection_agent = (

            plan_selection_agent

            if plan_selection_agent is not None

            else

            shared_ai_digital_twin_plan_selection_agent

        )





        self.protection_policy = (

            protection_policy

            if protection_policy is not None

            else shared_protection_mode_policy

        )





        self.explanation_agent = (

            explanation_agent

            if explanation_agent is not None

            else shared_ai_user_explanation_agent

        )





        self.publisher = (

            publisher

            if publisher is not None

            else publish_user_security_snapshot

        )





    # ============================================================

    # TIME

    # ============================================================



    @staticmethod

    def now_iso() -> str:



        return datetime.now(

            timezone.utc

        ).isoformat()





    # ============================================================

    # SAFE DICT

    # ============================================================



    @staticmethod

    def safe_dict(

        value: Any,

    ) -> Dict:



        return (

            value

            if isinstance(

                value,

                dict,

            )

            else {}

        )





    # ============================================================

    # PIPELINE STATUS

    # ============================================================



    def status(

        self,

    ) -> Dict:



        return {



            "pipeline":

                self.name,



            "version":

                self.VERSION,



            "schema_version":

                self.SCHEMA_VERSION,



            "stages": {



                "risk":

                    getattr(

                        self.risk_agent,

                        "VERSION",

                        None,

                    ),



                "response":

                    getattr(

                        self.response_agent,

                        "VERSION",

                        None,

                    ),



                "plan_selection":

                    getattr(

                        self.plan_selection_agent,

                        "VERSION",

                        None,

                    ),



                "protection_policy":

                    getattr(

                        self.protection_policy,

                        "VERSION",

                        None,

                    ),



                "user_explanation":

                    getattr(

                        self.explanation_agent,

                        "VERSION",

                        None,

                    ),

            },



            "publication_target":

                "UserSecurityAPIService",



            "http_ai_inference":

                False,



            "real_response_execution":

                False,



            "simulation_only":

                True,



            "execution_allowed":

                False,

        }





    # ============================================================

    # SIMULATION SAFETY

    # ============================================================



    @staticmethod

    def validate_safety(

        stage_name: str,

        payload: Dict,

    ) -> None:



        if not isinstance(

            payload,

            dict,

        ):



            raise TypeError(

                (

                    f"{stage_name} output "

                    "must be a dictionary."

                )

            )





        if (

            payload.get(

                "simulation_only"

            )

            is not True

        ):



            raise ValueError(

                (

                    f"{stage_name} crossed the "

                    "simulation boundary."

                )

            )





        if (

            payload.get(

                "execution_allowed"

            )

            is True

        ):



            raise ValueError(

                (

                    f"{stage_name} unexpectedly "

                    "allowed real execution."

                )

            )





        if (

            payload.get(

                "automatic_execution_allowed"

            )

            is True

        ):



            raise ValueError(

                (

                    f"{stage_name} unexpectedly "

                    "allowed automatic execution."

                )

            )





        if (

            payload.get(

                "real_response_executed"

            )

            is True

        ):



            raise ValueError(

                (

                    f"{stage_name} reported a "

                    "real response execution."

                )

            )





    # ============================================================

    # AI AVAILABILITY

    # ============================================================



    @staticmethod

    def require_ai(

        stage_name: str,

        payload: Dict,

    ) -> None:



        if (

            payload.get(

                "ai_available"

            )

            is not True

        ):



            raise RuntimeError(

                (

                    f"{stage_name} AI result "

                    "is unavailable."

                )

            )





    # ============================================================

    # IDENTITY CONSISTENCY

    # ============================================================



    @staticmethod

    def validate_identity(

        stage_name: str,

        payload: Dict,

        threat: Dict,

    ) -> None:



        expected = {



            "security_id":

                threat.get(

                    "id"

                ),



            "event_id":

                threat.get(

                    "event_id"

                ),



            "incident_id":

                threat.get(

                    "incident_id"

                ),

        }





        for (

            key,

            expected_value,

        ) in expected.items():



            actual_value = (

                payload.get(

                    key

                )

            )





            if (

                expected_value

                is None

                or

                actual_value

                is None

            ):



                continue





            if (

                str(

                    actual_value

                )

                !=

                str(

                    expected_value

                )

            ):



                raise ValueError(

                    (

                        f"{stage_name} changed "

                        f"{key}: "

                        f"{actual_value} != "

                        f"{expected_value}"

                    )

                )





    # ============================================================

    # PROCESS ONE CANONICAL THREAT

    # ============================================================



    def process(

        self,

        *,

        threat: Dict,



        protection_mode: str = (

            "RECOMMENDED"

        ),



        incident: Optional[Dict] = None,



        investigation: Optional[Dict] = None,



        enriched_evidence: Optional[Dict] = None,



        graph_rag_context: Optional[Any] = None,



        additional_context: Optional[Dict] = None,

    ) -> Dict:



        # --------------------------------------------------------

        # INPUT

        # --------------------------------------------------------



        if not isinstance(

            threat,

            dict,

        ):



            raise TypeError(

                "threat must be a dictionary."

            )





        security_id = (

            threat.get(

                "id"

            )

        )





        if not security_id:



            raise ValueError(

                (

                    "Canonical threat must "

                    "contain an id."

                )

            )





        logger.info(

            (

                "Starting user-security AI "

                "pipeline | SecurityID=%s"

            ),

            security_id,

        )





        # ========================================================

        # 7D.4 — AI RISK REASONING

        # ========================================================



        risk = (

            self.risk_agent.assess(



                threat=

                    threat,



                incident=

                    incident,



                investigation=

                    investigation,



                enriched_evidence=

                    enriched_evidence,



                graph_rag_context=

                    graph_rag_context,



                additional_context=

                    additional_context,

            )

        )

        # ========================================================

        # 7D.4 DIAGNOSTIC

        # ========================================================



        if (

            risk.get(

                "ai_available"

            )

            is not True

        ):



            logger.error(

                (

                    "7D.4 AI unavailable | "

                    "provider=%s | "

                    "model=%s | "

                    "provider_error=%s | "

                    "validation_error=%s | "

                    "repair_attempted=%s"

                ),

                risk.get(

                    "provider"

                ),

                risk.get(

                    "model"

                ),

                risk.get(

                    "provider_error"

                ),

                risk.get(

                    "output_validation_error"

                ),

                risk.get(

                    "output_repair_attempted"

                ),

            )



        self.validate_safety(

            "7D.4 AI Risk",

            risk,

        )





        self.require_ai(

            "7D.4 AI Risk",

            risk,

        )





        self.validate_identity(

            "7D.4 AI Risk",

            risk,

            threat,

        )





        # ========================================================

        # 7D.5 — AI RESPONSE RECOMMENDATION

        # ========================================================



        response = (

            self.response_agent.recommend(



                threat=

                    threat,



                risk_assessment=

                    risk,



                incident=

                    incident,



                investigation=

                    investigation,



                enriched_evidence=

                    enriched_evidence,



                graph_rag_context=

                    graph_rag_context,



                additional_context=

                    additional_context,

            )

        )





        if (
            response.get("ai_available")
            is not True
        ):
            logger.error(
                (
                    "7D.5 AI unavailable | "
                    "provider=%s | "
                    "model=%s | "
                    "provider_error_type=%s | "
                    "provider_error=%s | "
                    "validation_error=%s | "
                    "repair_attempted=%s"
                ),
                response.get("provider"),
                response.get("model"),
                response.get("provider_error_type"),
                response.get("provider_error"),
                response.get("output_validation_error"),
                response.get("output_repair_attempted"),
            )

        self.validate_safety(

            "7D.5 AI Response",

            response,

        )





        self.require_ai(

            "7D.5 AI Response",

            response,

        )





        self.validate_identity(

            "7D.5 AI Response",

            response,

            threat,

        )





        # ========================================================

        # 7D.6 — DIGITAL TWIN + AI PLAN SELECTION

        # ========================================================



        plan = (

            self.plan_selection_agent

            .select_plan(



                threat=

                    threat,



                risk_assessment=

                    risk,



                response_recommendation=

                    response,



                enriched_evidence=

                    enriched_evidence,



                incident=

                    incident,



                investigation=

                    investigation,

            )

        )





        if (
            str(
                plan.get("selection_status")
                or ""
            ).upper()
            == "AI_UNAVAILABLE"
        ):
            logger.error(
                (
                    "7D.6 AI unavailable | "
                    "provider=%s | "
                    "model=%s | "
                    "provider_error_type=%s | "
                    "provider_error=%s | "
                    "validation_error=%s | "
                    "repair_attempted=%s"
                ),
                plan.get("provider"),
                plan.get("model"),
                plan.get("provider_error_type"),
                plan.get("provider_error"),
                plan.get("output_validation_error"),
                plan.get("output_repair_attempted"),
            )

        self.validate_safety(

            "7D.6 Plan Selection",

            plan,

        )





        plan_status = (

            str(

                plan.get(

                    "selection_status"

                )

                or

                ""

            )

            .upper()

        )





        if (

            plan_status

            not in

            self.VALID_PLAN_STATUSES

        ):



            raise RuntimeError(

                (

                    "7D.6 did not produce a "

                    "usable plan-selection state: "

                    f"{plan_status or 'UNKNOWN'}"

                )

            )





        if (

            plan_status

            ==

            "SELECTED"

        ):



            self.require_ai(

                "7D.6 Plan Selection",

                plan,

            )





        self.validate_identity(

            "7D.6 Plan Selection",

            plan,

            threat,

        )





        # ========================================================

        # 7D.7 — USER PROTECTION MODE POLICY

        # ========================================================



        policy = (

            self.protection_policy.apply(



                mode=

                    protection_mode,



                threat=

                    threat,



                risk_assessment=

                    risk,



                response_recommendation=

                    response,



                plan_selection=

                    plan,

            )

        )





        self.validate_safety(

            "7D.7 Protection Policy",

            policy,

        )





        self.validate_identity(

            "7D.7 Protection Policy",

            policy,

            threat,

        )





        policy_decision = (

            str(

                policy.get(

                    "policy_decision"

                )

                or

                ""

            )

            .upper()

        )





        if (

            policy_decision

            not in

            self.VALID_POLICY_DECISIONS

        ):



            raise RuntimeError(

                (

                    "7D.7 returned unsupported "

                    "policy decision: "

                    f"{policy_decision}"

                )

            )





        # ========================================================

        # 7D.8 — AI USER EXPLANATION

        # ========================================================



        explanation = (

            self.explanation_agent.explain(



                threat=

                    threat,



                risk_assessment=

                    risk,



                response_recommendation=

                    response,



                plan_selection=

                    plan,



                protection_policy=

                    policy,

            )

        )





        if (
            explanation.get("ai_available")
            is not True
        ):
            logger.error(
                (
                    "7D.8 AI unavailable | "
                    "provider=%s | "
                    "model=%s | "
                    "provider_error_type=%s | "
                    "provider_error=%s | "
                    "validation_error=%s | "
                    "repair_attempted=%s"
                ),
                explanation.get("provider"),
                explanation.get("model"),
                explanation.get("provider_error_type"),
                explanation.get("provider_error"),
                explanation.get("output_validation_error"),
                explanation.get("output_repair_attempted"),
            )

        self.validate_safety(

            "7D.8 User Explanation",

            explanation,

        )





        self.require_ai(

            "7D.8 User Explanation",

            explanation,

        )





        self.validate_identity(

            "7D.8 User Explanation",

            explanation,

            threat,

        )





        if (

            explanation.get(

                "agent"

            )

            !=

            "AIUserExplanationAgent"

        ):



            raise ValueError(

                (

                    "Unexpected 7D.8 "

                    "explanation agent."

                )

            )





        if (

            explanation.get(

                "agent_version"

            )

            !=

            "7D.8-v1"

        ):



            raise ValueError(

                (

                    "Unexpected AI user "

                    "explanation version."

                )

            )





        if (

            explanation.get(

                "next_stage"

            )

            !=

            "USER_FACING_API"

        ):



            raise ValueError(

                (

                    "7D.8 output is not ready "

                    "for the user-facing API."

                )

            )





        # ========================================================

        # 7D.9 — INTERNAL SNAPSHOT PUBLICATION

        # ========================================================



        snapshot = (

            self.publisher(

                explanation

            )

        )





        self.validate_safety(

            "7D.9 Published Snapshot",

            snapshot,

        )





        logger.info(

            (

                "Published user-security "

                "snapshot | SecurityID=%s "

                "| Status=%s"

            ),

            security_id,

            snapshot.get(

                "status"

            ),

        )





        # ========================================================

        # RESULT

        # ========================================================



        return {



            "schema_version":

                self.SCHEMA_VERSION,



            "pipeline":

                self.name,



            "pipeline_version":

                self.VERSION,



            "processed_at":

                self.now_iso(),



            "security_id":

                security_id,



            "event_id":

                threat.get(

                    "event_id"

                ),



            "incident_id":

                threat.get(

                    "incident_id"

                ),



            "status":

                "PUBLISHED",



            "protection_mode":

                policy.get(

                    "protection_mode"

                ),



            "policy_decision":

                policy_decision,



            "display_status":

                explanation.get(

                    "display_status"

                ),



            "requires_user_confirmation":

                explanation.get(

                    "requires_user_confirmation"

                ),



            "stages": {



                "risk":

                    risk,



                "response":

                    response,



                "plan_selection":

                    plan,



                "protection_policy":

                    policy,



                "user_explanation":

                    explanation,

            },



            "published_snapshot":

                snapshot,



            "simulation_only":

                True,



            "execution_allowed":

                False,



            "automatic_execution_allowed":

                False,



            "real_response_executed":

                False,

        }







shared_user_security_runtime_pipeline = (

    UserSecurityRuntimePipeline()

)