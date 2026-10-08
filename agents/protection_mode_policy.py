from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional


# ================================================================
# SENTINEL-X 7D.7 — PROTECTION MODE POLICY
# ================================================================


class ProtectionModePolicy:
    """
    User-facing protection-mode policy for SENTINEL-X.

    This stage consumes the already-grounded outputs from:

        7D.4 AI Risk Reasoning
        7D.5 AI Response Recommendation
        7D.6 Digital Twin + AI Plan Selection

    It does NOT perform threat inference.

    It decides how the user's selected protection mode should treat
    the selected Digital Twin plan.

    IMPORTANT:
        Phase 7 remains simulation-only.

        Therefore even STRICT mode never performs real endpoint
        containment in this build.

        This policy can express future protection intent, but:
            execution_allowed = False
            automatic_execution_allowed = False
            real_response_executed = False
    """

    VERSION = "7D.7-v1"

    SCHEMA_VERSION = (
        "sentinelx.ai.protection-mode-policy.v1"
    )

    VALID_MODES = {
        "RECOMMENDED",
        "STRICT",
        "ASK_ME",
        "MONITOR_ONLY",
    }

    MODE_ALIASES = {
        "RECOMMENDED": "RECOMMENDED",
        "RECOMMEND": "RECOMMENDED",
        "DEFAULT": "RECOMMENDED",

        "STRICT": "STRICT",

        "ASK_ME": "ASK_ME",
        "ASK ME": "ASK_ME",
        "ASK": "ASK_ME",

        "MONITOR_ONLY": "MONITOR_ONLY",
        "MONITOR ONLY": "MONITOR_ONLY",
        "MONITOR": "MONITOR_ONLY",
    }

    MODE_METADATA = {
        "RECOMMENDED": {
            "display_name": "Recommended",
            "legacy_autonomy_level": 2,
            "description": (
                "Follow grounded AI and Digital Twin recommendations. "
                "Ask the user when evidence is suspicious/uncertain; "
                "prepare protection for likely malicious or malicious "
                "activity."
            ),
        },
        "STRICT": {
            "display_name": "Strict",
            "legacy_autonomy_level": 4,
            "description": (
                "Use a more protective posture. Grounded suspicious "
                "activity may become protection-eligible after Digital "
                "Twin validation, while uncertain activity still asks "
                "the user."
            ),
        },
        "ASK_ME": {
            "display_name": "Ask Me",
            "legacy_autonomy_level": 3,
            "description": (
                "Never advance a disruptive protection plan without "
                "explicit user confirmation."
            ),
        },
        "MONITOR_ONLY": {
            "display_name": "Monitor Only",
            "legacy_autonomy_level": 0,
            "description": (
                "Never advance disruptive protection. Preserve the "
                "selected Digital Twin plan only as a preview."
            ),
        },
    }

    DISRUPTIVE_ACTIONS = {
        "QUARANTINE_FILE",
        "TERMINATE_PROCESS",
        "BLOCK_NETWORK",
        "REMEDIATE_PERSISTENCE",
        "ISOLATE_ENDPOINT",
    }

    PROTECTION_DECISIONS = {
        "MONITOR",
        "ASK_USER",
        "PROTECT_PREVIEW",
    }

    # ============================================================
    # HELPERS
    # ============================================================

    @staticmethod
    def now_iso() -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def safe_dict(
        value: Any,
    ) -> Dict:
        return (
            value
            if isinstance(value, dict)
            else {}
        )

    @staticmethod
    def safe_list(
        value: Any,
    ) -> list:
        return (
            value
            if isinstance(value, list)
            else []
        )

    @staticmethod
    def safe_string(
        value: Any,
    ) -> str:
        return str(
            value or ""
        ).strip()

    # ============================================================
    # MODE
    # ============================================================

    def normalize_mode(
        self,
        mode: str,
    ) -> str:
        normalized = (
            self.safe_string(mode)
            .upper()
            .replace("-", "_")
        )

        normalized = (
            self.MODE_ALIASES.get(
                normalized,
                normalized,
            )
        )

        if normalized not in self.VALID_MODES:
            raise ValueError(
                "Unsupported protection mode: "
                f"{mode}. Allowed modes: "
                f"{sorted(self.VALID_MODES)}"
            )

        return normalized

    def mode_metadata(
        self,
        mode: str,
    ) -> Dict:
        mode = self.normalize_mode(mode)
        return deepcopy(
            self.MODE_METADATA[
                mode
            ]
        )

    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict:
        return {
            "policy": self.__class__.__name__,
            "version": self.VERSION,
            "schema_version": self.SCHEMA_VERSION,
            "modes": {
                key: deepcopy(value)
                for key, value
                in self.MODE_METADATA.items()
            },
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_execution": False,
        }

    # ============================================================
    # SELECTED PLAN
    # ============================================================

    def selected_plan(
        self,
        plan_selection: Dict,
    ) -> Dict:
        return self.safe_dict(
            plan_selection.get(
                "selected_plan"
            )
        )

    def selected_action_types(
        self,
        plan_selection: Dict,
    ) -> set:
        plan = self.selected_plan(
            plan_selection
        )

        return {
            self.safe_string(
                action.get(
                    "action_type"
                )
            ).upper()

            for action in self.safe_list(
                plan.get(
                    "actions"
                )
            )

            if self.safe_string(
                action.get(
                    "action_type"
                )
            )
        }

    def has_disruptive_plan(
        self,
        plan_selection: Dict,
    ) -> bool:
        return bool(
            self.selected_action_types(
                plan_selection
            )
            &
            self.DISRUPTIVE_ACTIONS
        )

    # ============================================================
    # INPUT SAFETY
    # ============================================================

    def validate_upstream_safety(
        self,
        *,
        response_recommendation: Dict,
        plan_selection: Dict,
    ) -> None:
        """
        7D.7 must never accept an upstream result that claims real
        response execution occurred.
        """

        for name, payload in (
            (
                "response_recommendation",
                response_recommendation,
            ),
            (
                "plan_selection",
                plan_selection,
            ),
        ):
            payload = self.safe_dict(
                payload
            )

            if (
                payload.get(
                    "real_response_executed"
                )
                is True
            ):
                raise ValueError(
                    f"{name} indicates real response execution."
                )

            if (
                payload.get(
                    "execution_allowed"
                )
                is True
            ):
                raise ValueError(
                    f"{name} unexpectedly permits real execution."
                )

            if (
                payload.get(
                    "automatic_execution_allowed"
                )
                is True
            ):
                raise ValueError(
                    f"{name} unexpectedly permits automatic execution."
                )

    # ============================================================
    # DECISION CORE
    # ============================================================

    def determine_decision(
        self,
        *,
        mode: str,
        threat_assessment: str,
        response_recommendation: Dict,
        plan_selection: Dict,
    ) -> Dict:
        """
        Determine user-facing protection behavior.

        This is deliberately deterministic policy logic.
        AI reasoning has already happened in 7D.4–7D.6.
        """

        mode = self.normalize_mode(
            mode
        )

        assessment = (
            self.safe_string(
                threat_assessment
            )
            .upper()
        )

        response_recommendation = (
            self.safe_dict(
                response_recommendation
            )
        )

        plan_selection = (
            self.safe_dict(
                plan_selection
            )
        )

        digital_twin_required = bool(
            response_recommendation.get(
                "digital_twin_required",
                False,
            )
        )

        selection_status = (
            self.safe_string(
                plan_selection.get(
                    "selection_status"
                )
            )
            .upper()
        )

        selected_plan = (
            self.selected_plan(
                plan_selection
            )
        )

        has_plan = bool(
            selected_plan
        )

        disruptive_plan = (
            self.has_disruptive_plan(
                plan_selection
            )
        )

        # --------------------------------------------------------
        # MONITOR ONLY always wins.
        # --------------------------------------------------------

        if mode == "MONITOR_ONLY":
            return {
                "decision": "MONITOR",
                "reason": (
                    "Monitor Only mode suppresses disruptive "
                    "protection advancement. Any simulated plan "
                    "is retained as preview evidence only."
                ),
                "requires_user_confirmation": False,
                "policy_eligible_for_protection": False,
                "automatic_protection_intent": False,
            }

        # --------------------------------------------------------
        # Benign / low concern cannot become protection merely
        # because a stale/inconsistent upstream plan exists.
        # --------------------------------------------------------

        if assessment in {
            "BENIGN",
            "LOW_CONCERN",
        }:
            return {
                "decision": "MONITOR",
                "reason": (
                    f"{assessment} activity remains in monitoring "
                    "under every protection mode."
                ),
                "requires_user_confirmation": False,
                "policy_eligible_for_protection": False,
                "automatic_protection_intent": False,
            }

        # --------------------------------------------------------
        # No disruptive candidate / no selected plan.
        # --------------------------------------------------------

        if (
            not digital_twin_required
            or
            not has_plan
            or
            not disruptive_plan
        ):
            # If a disruptive path was expected but the AI plan
            # selection is unavailable, fail safely to ASK_USER
            # rather than pretend protection can proceed.
            if (
                digital_twin_required
                and
                selection_status
                in {
                    "AI_UNAVAILABLE",
                    "UNAVAILABLE",
                    "FAILED",
                }
            ):
                return {
                    "decision": "ASK_USER",
                    "reason": (
                        "A disruptive response was proposed, but "
                        "the Digital Twin AI plan selection is "
                        "unavailable. User confirmation/review is "
                        "required before any future protection step."
                    ),
                    "requires_user_confirmation": True,
                    "policy_eligible_for_protection": False,
                    "automatic_protection_intent": False,
                }

            return {
                "decision": "MONITOR",
                "reason": (
                    "No validated disruptive Digital Twin plan "
                    "requires protection-mode authorization."
                ),
                "requires_user_confirmation": False,
                "policy_eligible_for_protection": False,
                "automatic_protection_intent": False,
            }

        # --------------------------------------------------------
        # ASK ME
        # --------------------------------------------------------

        if mode == "ASK_ME":
            return {
                "decision": "ASK_USER",
                "reason": (
                    "Ask Me mode requires explicit user "
                    "confirmation before any disruptive protection "
                    "plan may advance."
                ),
                "requires_user_confirmation": True,
                "policy_eligible_for_protection": False,
                "automatic_protection_intent": False,
            }

        # --------------------------------------------------------
        # UNCERTAIN always asks.
        # --------------------------------------------------------

        if assessment == "UNCERTAIN":
            return {
                "decision": "ASK_USER",
                "reason": (
                    "Uncertain security evidence requires explicit "
                    "user confirmation regardless of Recommended "
                    "or Strict mode."
                ),
                "requires_user_confirmation": True,
                "policy_eligible_for_protection": False,
                "automatic_protection_intent": False,
            }

        # --------------------------------------------------------
        # SUSPICIOUS
        # --------------------------------------------------------

        if assessment == "SUSPICIOUS":
            if mode == "STRICT":
                return {
                    "decision": "PROTECT_PREVIEW",
                    "reason": (
                        "Strict mode permits a grounded suspicious "
                        "Digital Twin plan to become protection-"
                        "eligible. Real execution remains disabled "
                        "in the current prototype."
                    ),
                    "requires_user_confirmation": False,
                    "policy_eligible_for_protection": True,
                    "automatic_protection_intent": True,
                }

            return {
                "decision": "ASK_USER",
                "reason": (
                    "Recommended mode asks the user before advancing "
                    "a disruptive plan for SUSPICIOUS-only evidence."
                ),
                "requires_user_confirmation": True,
                "policy_eligible_for_protection": False,
                "automatic_protection_intent": False,
            }

        # --------------------------------------------------------
        # LIKELY_MALICIOUS / MALICIOUS
        # --------------------------------------------------------

        if assessment in {
            "LIKELY_MALICIOUS",
            "MALICIOUS",
        }:
            return {
                "decision": "PROTECT_PREVIEW",
                "reason": (
                    f"{mode} mode accepts the validated Digital "
                    f"Twin plan as a protection candidate for "
                    f"{assessment} activity. The current Phase 7 "
                    "build remains simulation-only."
                ),
                "requires_user_confirmation": False,
                "policy_eligible_for_protection": True,
                "automatic_protection_intent": True,
            }

        # --------------------------------------------------------
        # Unknown assessment: safe fallback.
        # --------------------------------------------------------

        return {
            "decision": "ASK_USER",
            "reason": (
                "Threat assessment is unknown to the protection "
                "policy. Explicit user review is required."
            ),
            "requires_user_confirmation": True,
            "policy_eligible_for_protection": False,
            "automatic_protection_intent": False,
        }

    # ============================================================
    # MAIN
    # ============================================================

    def apply(
        self,
        *,
        mode: str,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        plan_selection: Dict,
    ) -> Dict:
        if not isinstance(
            threat,
            dict,
        ):
            raise TypeError(
                "threat must be a dictionary."
            )

        if not isinstance(
            risk_assessment,
            dict,
        ):
            raise TypeError(
                "risk_assessment must be a dictionary."
            )

        if not isinstance(
            response_recommendation,
            dict,
        ):
            raise TypeError(
                "response_recommendation must be a dictionary."
            )

        if not isinstance(
            plan_selection,
            dict,
        ):
            raise TypeError(
                "plan_selection must be a dictionary."
            )

        mode = self.normalize_mode(
            mode
        )

        self.validate_upstream_safety(
            response_recommendation=
                response_recommendation,
            plan_selection=
                plan_selection,
        )

        assessment = (
            self.safe_string(
                risk_assessment.get(
                    "threat_assessment"
                )
            )
            .upper()
        )

        policy = self.determine_decision(
            mode=mode,
            threat_assessment=assessment,
            response_recommendation=
                response_recommendation,
            plan_selection=
                plan_selection,
        )

        decision = (
            policy[
                "decision"
            ]
        )

        if decision not in self.PROTECTION_DECISIONS:
            raise ValueError(
                f"Invalid protection decision: {decision}"
            )

        selected_plan = deepcopy(
            self.selected_plan(
                plan_selection
            )
        )

        selected_plan_id = (
            selected_plan.get(
                "plan_id"
            )
            if selected_plan
            else None
        )

        mode_info = self.mode_metadata(
            mode
        )

        upstream_requires_approval = bool(
            plan_selection.get(
                "requires_analyst_approval",
                False,
            )
        )

        protection_candidate = bool(
            selected_plan
            and
            self.has_disruptive_plan(
                plan_selection
            )
        )

        # Even when a mode expresses future automatic protection
        # intent, this prototype remains locked.
        automatic_protection_intent = bool(
            policy[
                "automatic_protection_intent"
            ]
        )

        return {
            "schema_version":
                self.SCHEMA_VERSION,

            "policy":
                self.__class__.__name__,

            "policy_version":
                self.VERSION,

            "evaluated_at":
                self.now_iso(),

            "security_id":
                threat.get(
                    "id"
                ),

            "event_id":
                threat.get(
                    "event_id"
                ),

            "incident_id":
                (
                    threat.get(
                        "incident_id"
                    )
                    or
                    plan_selection.get(
                        "incident_id"
                    )
                ),

            "protection_mode":
                mode,

            "protection_mode_display":
                mode_info[
                    "display_name"
                ],

            "mode_description":
                mode_info[
                    "description"
                ],

            "legacy_autonomy_level":
                mode_info[
                    "legacy_autonomy_level"
                ],

            "risk_level":
                risk_assessment.get(
                    "risk_level"
                ),

            "threat_assessment":
                assessment,

            "response_strategy":
                response_recommendation.get(
                    "response_strategy"
                ),

            "plan_selection_status":
                plan_selection.get(
                    "selection_status"
                ),

            "selected_plan_id":
                selected_plan_id,

            "selected_plan_preview":
                selected_plan
                if selected_plan
                else None,

            "protection_candidate":
                protection_candidate,

            "policy_decision":
                decision,

            "policy_reason":
                policy[
                    "reason"
                ],

            "requires_user_confirmation":
                policy[
                    "requires_user_confirmation"
                ],

            "upstream_analyst_approval_required":
                upstream_requires_approval,

            "policy_eligible_for_protection":
                policy[
                    "policy_eligible_for_protection"
                ],

            "automatic_protection_intent":
                automatic_protection_intent,

            "protection_intent":
                (
                    "PROTECT_WHEN_EXECUTION_LAYER_IS_ENABLED"
                    if automatic_protection_intent
                    else
                    "NO_AUTOMATIC_PROTECTION_INTENT"
                ),

            # ----------------------------------------------------
            # HARD PHASE-7 SAFETY BOUNDARY
            # ----------------------------------------------------

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,

            "next_stage":
                "AI_USER_EXPLANATION",
        }


# ================================================================
# SHARED INSTANCE
# ================================================================


shared_protection_mode_policy = (
    ProtectionModePolicy()
)
