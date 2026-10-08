from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

from agents.protection_mode_policy import (
    shared_protection_mode_policy,
)


# ================================================================
# SENTINEL-X 7D.9 — USER-FACING SECURITY API
# ================================================================


class UserSecuritySnapshotStore:
    """
    Small read-model store for frontend-safe 7D.8 explanation output.

    IMPORTANT:
        - No endpoint response action is executed here.
        - No security inference happens here.
        - Only already-grounded 7D.8 explanation snapshots are stored.
        - Current prototype storage is in-memory.
    """

    VERSION = "7D.9-v1"

    SCHEMA_VERSION = (
        "sentinelx.user-security.snapshot.v1"
    )


    def __init__(
        self,
    ):

        self._lock = (
            RLock()
        )

        self._items: Dict[
            str,
            Dict,
        ] = {}


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
            if isinstance(
                value,
                dict,
            )
            else {}
        )


    @staticmethod
    def safe_list(
        value: Any,
    ) -> List:

        return (
            value
            if isinstance(
                value,
                list,
            )
            else []
        )


    @staticmethod
    def safe_string(
        value: Any,
    ) -> str:

        return str(
            value
            or ""
        ).strip()


    # ============================================================
    # SNAPSHOT VALIDATION
    # ============================================================

    def validate_explanation(
        self,
        explanation: Dict,
    ) -> None:

        if not isinstance(
            explanation,
            dict,
        ):

            raise TypeError(
                "explanation must be a dictionary."
            )


        security_id = (
            self.safe_string(
                explanation.get(
                    "security_id"
                )
            )
        )


        if not security_id:

            raise ValueError(
                "security_id is required."
            )


        if (
            self.safe_string(
                explanation.get(
                    "agent"
                )
            )
            !=
            "AIUserExplanationAgent"
        ):

            raise ValueError(
                (
                    "Snapshot must originate from "
                    "AIUserExplanationAgent."
                )
            )


        if (
            self.safe_string(
                explanation.get(
                    "agent_version"
                )
            )
            !=
            "7D.8-v1"
        ):

            raise ValueError(
                (
                    "Unsupported AI user explanation "
                    "version."
                )
            )


        policy_decision = (
            self.safe_string(
                explanation.get(
                    "policy_decision"
                )
            )
            .upper()
        )


        if policy_decision not in {
            "MONITOR",
            "ASK_USER",
            "PROTECT_PREVIEW",
        }:

            raise ValueError(
                (
                    "Unsupported policy_decision: "
                    f"{policy_decision}"
                )
            )


        display_status = (
            self.safe_string(
                explanation.get(
                    "display_status"
                )
            )
            .upper()
        )


        expected_status = {

            "MONITOR":
                "MONITORING",

            "ASK_USER":
                "REVIEW_REQUIRED",

            "PROTECT_PREVIEW":
                "PROTECTION_PREPARED",

        }[
            policy_decision
        ]


        if (
            display_status
            !=
            expected_status
        ):

            raise ValueError(
                (
                    "display_status does not match "
                    f"policy_decision. Expected "
                    f"{expected_status}, got "
                    f"{display_status}."
                )
            )


        if (
            explanation.get(
                "simulation_only"
            )
            is not True
        ):

            raise ValueError(
                (
                    "7D.9 accepts simulation-only "
                    "explanations only."
                )
            )


        if (
            explanation.get(
                "execution_allowed"
            )
            is not False
        ):

            raise ValueError(
                (
                    "7D.9 cannot publish a snapshot "
                    "that allows execution."
                )
            )


        if (
            explanation.get(
                "automatic_execution_allowed"
            )
            is not False
        ):

            raise ValueError(
                (
                    "7D.9 cannot publish a snapshot "
                    "that allows automatic execution."
                )
            )


        if (
            explanation.get(
                "real_response_executed"
            )
            is not False
        ):

            raise ValueError(
                (
                    "7D.9 cannot publish a snapshot "
                    "claiming real response execution."
                )
            )


        required_text = [

            "headline",
            "plain_language_summary",
            "why_it_matters",
            "recommended_action_explanation",
            "uncertainty_note",
            "digital_twin_note",
            "execution_message",
        ]


        for field in (
            required_text
        ):

            if not self.safe_string(
                explanation.get(
                    field
                )
            ):

                raise ValueError(
                    f"{field} is required."
                )


        why_flagged = (
            self.safe_list(
                explanation.get(
                    "why_flagged"
                )
            )
        )


        if not (
            1
            <=
            len(
                why_flagged
            )
            <=
            4
        ):

            raise ValueError(
                (
                    "why_flagged must contain "
                    "1 to 4 items."
                )
            )


    # ============================================================
    # NORMALIZE FRONTEND CONTRACT
    # ============================================================

    def normalize(
        self,
        explanation: Dict,
    ) -> Dict:

        self.validate_explanation(
            explanation
        )


        security_id = (
            self.safe_string(
                explanation[
                    "security_id"
                ]
            )
        )


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "snapshot_version":
                self.VERSION,

            "published_at":
                self.now_iso(),

            "security_id":
                security_id,

            "event_id":
                explanation.get(
                    "event_id"
                ),

            "incident_id":
                explanation.get(
                    "incident_id"
                ),

            # ----------------------------------------------------
            # PRIMARY USER STATE
            # ----------------------------------------------------

            "status":
                explanation.get(
                    "display_status"
                ),

            "headline":
                explanation.get(
                    "headline"
                ),

            "summary":
                explanation.get(
                    "plain_language_summary"
                ),

            "risk": {

                "level":
                    explanation.get(
                        "risk_level"
                    ),

                "assessment":
                    explanation.get(
                        "threat_assessment"
                    ),

                "confidence":
                    explanation.get(
                        "risk_confidence"
                    ),
            },

            # ----------------------------------------------------
            # WHY
            # ----------------------------------------------------

            "why_flagged":
                deepcopy(
                    self.safe_list(
                        explanation.get(
                            "why_flagged"
                        )
                    )
                ),

            "why_it_matters":
                explanation.get(
                    "why_it_matters"
                ),

            "uncertainty_note":
                explanation.get(
                    "uncertainty_note"
                ),

            # ----------------------------------------------------
            # PROTECTION
            # ----------------------------------------------------

            "protection": {

                "mode":
                    explanation.get(
                        "protection_mode"
                    ),

                "mode_display":
                    explanation.get(
                        "protection_mode_display"
                    ),

                "policy_decision":
                    explanation.get(
                        "policy_decision"
                    ),

                "requires_user_confirmation":
                    bool(
                        explanation.get(
                            "requires_user_confirmation",
                            False,
                        )
                    ),

                "user_prompt":
                    explanation.get(
                        "user_prompt"
                    ),

                "execution_message":
                    explanation.get(
                        "execution_message"
                    ),
            },

            # ----------------------------------------------------
            # DIGITAL TWIN / RESPONSE PREVIEW
            # ----------------------------------------------------

            "response": {

                "selected_plan_id":
                    explanation.get(
                        "selected_plan_id"
                    ),

                "planned_actions":
                    deepcopy(
                        self.safe_list(
                            explanation.get(
                                "planned_actions"
                            )
                        )
                    ),

                "explanation":
                    explanation.get(
                        "recommended_action_explanation"
                    ),

                "digital_twin_note":
                    explanation.get(
                        "digital_twin_note"
                    ),
            },

            # ----------------------------------------------------
            # TECHNICAL ACCESS
            # ----------------------------------------------------

            "technical_details_available":
                bool(
                    explanation.get(
                        "technical_details_available",
                        True,
                    )
                ),

            "source_versions":
                deepcopy(
                    self.safe_dict(
                        explanation.get(
                            "source_versions"
                        )
                    )
                ),

            # ----------------------------------------------------
            # HARD SAFETY
            # ----------------------------------------------------

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,
        }


    # ============================================================
    # WRITE — INTERNAL ONLY
    # ============================================================

    def publish(
        self,
        explanation: Dict,
    ) -> Dict:

        snapshot = (
            self.normalize(
                explanation
            )
        )


        security_id = (
            snapshot[
                "security_id"
            ]
        )


        with self._lock:

            self._items[
                security_id
            ] = deepcopy(
                snapshot
            )


        return deepcopy(
            snapshot
        )


    # ============================================================
    # READ
    # ============================================================

    def get(
        self,
        security_id: str,
    ) -> Optional[Dict]:

        security_id = (
            self.safe_string(
                security_id
            )
        )


        if not security_id:

            return None


        with self._lock:

            item = (
                self._items.get(
                    security_id
                )
            )


            return (
                deepcopy(
                    item
                )
                if item
                is not None
                else None
            )


    def list(
        self,
        limit: int = 100,
    ) -> List[Dict]:

        try:

            limit = int(
                limit
            )

        except (
            TypeError,
            ValueError,
        ):

            limit = 100


        limit = max(
            1,
            min(
                limit,
                1000,
            ),
        )


        with self._lock:

            items = list(
                self._items.values()
            )


        items.sort(

            key=lambda item:
                self.safe_string(
                    item.get(
                        "published_at"
                    )
                ),

            reverse=True,
        )


        return deepcopy(
            items[
                :limit
            ]
        )


    def count(
        self,
    ) -> int:

        with self._lock:

            return len(
                self._items
            )


    # Used by validation only.
    def clear(
        self,
    ) -> None:

        with self._lock:

            self._items.clear()


# ================================================================
# USER SECURITY API SERVICE
# ================================================================


class UserSecurityAPIService:
    """
    Read-only frontend adapter.

    HTTP routes NEVER create AI decisions and NEVER execute actions.
    """

    VERSION = "7D.9-v1"

    SCHEMA_VERSION = (
        "sentinelx.user-security.api.v1"
    )


    def __init__(
        self,
        store=None,
        protection_mode_policy=None,
    ):

        self.name = (
            "UserSecurityAPIService"
        )


        self.store = (
            store
            if store is not None
            else UserSecuritySnapshotStore()
        )


        self.protection_mode_policy = (
            protection_mode_policy
            if protection_mode_policy is not None
            else shared_protection_mode_policy
        )


    @staticmethod
    def now_iso() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # INTERNAL PUBLISH HOOK
    # ============================================================

    def publish_explanation(
        self,
        explanation: Dict,
    ) -> Dict:

        return (
            self.store.publish(
                explanation
            )
        )


    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict:

        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "service":
                self.name,

            "version":
                self.VERSION,

            "status":
                "READY",

            "snapshot_count":
                self.store.count(),

            "read_only_http_api":
                True,

            "ai_inference_in_http_layer":
                False,

            "response_execution_in_http_layer":
                False,

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_execution":
                False,

            "timestamp":
                self.now_iso(),
        }


    # ============================================================
    # MODES
    # ============================================================

    def protection_modes(
        self,
    ) -> Dict:

        policy_status = (
            self.protection_mode_policy
            .status()
        )


        modes = (
            policy_status.get(
                "modes"
            )
            or {}
        )


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "count":
                len(
                    modes
                ),

            "default_mode":
                "RECOMMENDED",

            "modes":
                deepcopy(
                    modes
                ),

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


    # ============================================================
    # LIST
    # ============================================================

    def list_threats(
        self,
        limit: int = 100,
    ) -> Dict:

        items = (
            self.store.list(
                limit=limit
            )
        )


        summaries = []


        for item in items:

            summaries.append({

                "security_id":
                    item.get(
                        "security_id"
                    ),

                "event_id":
                    item.get(
                        "event_id"
                    ),

                "incident_id":
                    item.get(
                        "incident_id"
                    ),

                "status":
                    item.get(
                        "status"
                    ),

                "headline":
                    item.get(
                        "headline"
                    ),

                "risk":
                    deepcopy(
                        item.get(
                            "risk"
                        )
                        or
                        {}
                    ),

                "protection":
                    deepcopy(
                        item.get(
                            "protection"
                        )
                        or
                        {}
                    ),

                "published_at":
                    item.get(
                        "published_at"
                    ),
            })


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "count":
                len(
                    summaries
                ),

            "threats":
                summaries,

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


    # ============================================================
    # DETAIL
    # ============================================================

    def get_threat(
        self,
        security_id: str,
    ) -> Dict:

        item = (
            self.store.get(
                security_id
            )
        )


        if item is None:

            raise KeyError(
                security_id
            )


        return item


# ================================================================
# SHARED SERVICE
# ================================================================


shared_user_security_api_service = (
    UserSecurityAPIService()
)


# ================================================================
# INTERNAL PUBLISH FUNCTION
# ================================================================


def publish_user_security_snapshot(
    explanation: Dict,
) -> Dict:
    """
    Call this from the internal 7D.8/7D.11 workflow after a valid
    AIUserExplanationAgent result is produced.

    This function is NOT exposed as an HTTP mutation endpoint.
    """

    return (
        shared_user_security_api_service
        .publish_explanation(
            explanation
        )
    )


# ================================================================
# ROUTER FACTORY
# ================================================================


def build_user_security_router(
    service=None,
) -> APIRouter:

    service = (
        service
        if service is not None
        else shared_user_security_api_service
    )


    router = APIRouter(

        prefix=
            "/api/v1/user-security",

        tags=[
            "User Security"
        ],
    )


    # ------------------------------------------------------------
    # STATUS
    # ------------------------------------------------------------

    @router.get(
        "/status"
    )
    def get_user_security_status():

        return (
            service.status()
        )


    # ------------------------------------------------------------
    # MODES
    # ------------------------------------------------------------

    @router.get(
        "/protection-modes"
    )
    def get_protection_modes():

        return (
            service
            .protection_modes()
        )


    # ------------------------------------------------------------
    # USER-FACING THREAT LIST
    # ------------------------------------------------------------

    @router.get(
        "/threats"
    )
    def list_user_security_threats(
        limit: int = 100,
    ):

        return (
            service.list_threats(
                limit=limit
            )
        )


    # ------------------------------------------------------------
    # USER-FACING THREAT DETAIL
    # ------------------------------------------------------------

    @router.get(
        "/threats/{security_id}"
    )
    def get_user_security_threat(
        security_id: str,
    ):

        try:

            return (
                service.get_threat(
                    security_id
                )
            )


        except KeyError:

            raise HTTPException(

                status_code=
                    404,

                detail=(
                    "No user-facing security snapshot "
                    f"exists for {security_id}."
                ),
            )


    return router


# ================================================================
# DEFAULT ROUTER
# ================================================================


router = (
    build_user_security_router()
)
