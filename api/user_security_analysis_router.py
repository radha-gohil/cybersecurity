from __future__ import annotations

import logging
import threading
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from agents.user_security_runtime_pipeline import (
    shared_user_security_runtime_pipeline,
)
from api.user_security_router import (
    shared_user_security_api_service,
)


logger = logging.getLogger(__name__)


# ================================================================
# SENTINEL-X ON-DEMAND USER SECURITY ANALYSIS
# ================================================================

ANALYSIS_VERSION = "7D.12-on-demand-v1"
ANALYSIS_SCHEMA_VERSION = "sentinelx.user-security.analysis.v1"


class UserSecurityAnalyzeRequest(BaseModel):
    protection_mode: str = Field(
        default="RECOMMENDED",
        description=(
            "Protection mode passed to the existing 7D.7 policy stage. "
            "No real endpoint action is executed."
        ),
    )
    force: bool = Field(
        default=False,
        description=(
            "Re-run AI analysis even when a cached snapshot already exists."
        ),
    )


# Resolver is configured by api.main after the canonical threat builder
# has been defined. This avoids circular imports between this router and
# api.main.
_threat_resolver: Optional[Callable[[str], Optional[Dict]]] = None


# Per-threat job state. This is intentionally in-memory because the
# current 7D.9 snapshot store is also in-memory. A later persistence phase
# can move both to SQLite/Postgres without changing the frontend contract.
_jobs: Dict[str, Dict] = {}
_jobs_lock = threading.RLock()


# Only one complete LLM reasoning chain is allowed to execute at a time.
# This prevents a user rapidly opening several threats from creating a
# burst of 7D.4/7D.5/7D.6/7D.8 provider calls.
_execution_lock = threading.Lock()


# ================================================================
# HELPERS
# ================================================================


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()



def _safe_string(value: Any) -> str:
    return str(value or "").strip()



def _snapshot_or_none(security_id: str) -> Optional[Dict]:
    try:
        return shared_user_security_api_service.get_threat(security_id)
    except KeyError:
        return None



def _set_job(
    security_id: str,
    *,
    state: str,
    protection_mode: Optional[str] = None,
    error: Optional[str] = None,
    cached: bool = False,
    started_at: Optional[str] = None,
    completed_at: Optional[str] = None,
) -> Dict:
    with _jobs_lock:
        current = deepcopy(_jobs.get(security_id) or {})

        attempts = int(current.get("attempts") or 0)
        if state == "PENDING" and current.get("state") not in {
            "PENDING",
            "PROCESSING",
        }:
            attempts += 1

        payload = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "analysis_version": ANALYSIS_VERSION,
            "security_id": security_id,
            "state": state,
            "protection_mode": (
                protection_mode
                or current.get("protection_mode")
                or "RECOMMENDED"
            ),
            "attempts": attempts,
            "cached": bool(cached),
            "error": error,
            "requested_at": (
                current.get("requested_at")
                or _now_iso()
            ),
            "started_at": (
                started_at
                if started_at is not None
                else current.get("started_at")
            ),
            "completed_at": (
                completed_at
                if completed_at is not None
                else current.get("completed_at")
            ),
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }

        _jobs[security_id] = payload
        return deepcopy(payload)



def _job_or_default(security_id: str) -> Dict:
    snapshot = _snapshot_or_none(security_id)

    with _jobs_lock:
        current = deepcopy(_jobs.get(security_id) or {})

    # An active or failed explicit re-analysis state takes precedence
    # over an older cached snapshot. The snapshot remains readable, but
    # status accurately reports what the newest requested job is doing.
    if current.get("state") in {
        "PENDING",
        "PROCESSING",
        "FAILED",
    }:
        current["snapshot_available"] = snapshot is not None
        return current

    if snapshot is not None:
        return {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "analysis_version": ANALYSIS_VERSION,
            "security_id": security_id,
            "state": "READY",
            "protection_mode": (
                current.get("protection_mode")
                or snapshot.get("protection", {}).get("mode")
                or "RECOMMENDED"
            ),
            "attempts": int(current.get("attempts") or 0),
            "cached": True,
            "error": None,
            "requested_at": current.get("requested_at"),
            "started_at": current.get("started_at"),
            "completed_at": (
                current.get("completed_at")
                or snapshot.get("published_at")
            ),
            "snapshot_available": True,
            "published_at": snapshot.get("published_at"),
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }

    if current:
        current["snapshot_available"] = False
        return current

    return {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "analysis_version": ANALYSIS_VERSION,
        "security_id": security_id,
        "state": "NOT_STARTED",
        "protection_mode": "RECOMMENDED",
        "attempts": 0,
        "cached": False,
        "error": None,
        "requested_at": None,
        "started_at": None,
        "completed_at": None,
        "snapshot_available": False,
        "simulation_only": True,
        "execution_allowed": False,
        "automatic_execution_allowed": False,
        "real_response_executed": False,
    }


# ================================================================
# CONFIGURATION FROM api.main
# ================================================================


def configure_user_security_analysis(
    threat_resolver: Callable[[str], Optional[Dict]],
) -> None:
    global _threat_resolver

    if not callable(threat_resolver):
        raise TypeError("threat_resolver must be callable.")

    _threat_resolver = threat_resolver

    logger.info(
        "SENTINEL-X on-demand user-security analysis resolver configured."
    )


# ================================================================
# BACKGROUND WORKER
# ================================================================


def _run_analysis(
    *,
    security_id: str,
    protection_mode: str,
) -> None:
    try:
        # Queueing multiple distinct threats is allowed, but only one
        # complete provider-heavy reasoning chain executes at once.
        with _execution_lock:
            _set_job(
                security_id,
                state="PROCESSING",
                protection_mode=protection_mode,
                started_at=_now_iso(),
                completed_at=None,
            )

            if _threat_resolver is None:
                raise RuntimeError(
                    "Canonical threat resolver is not configured."
                )

            threat = _threat_resolver(security_id)

            if not isinstance(threat, dict):
                raise LookupError(
                    f"Canonical threat {security_id} was not found."
                )

            incident = threat.get("incident")
            if not isinstance(incident, dict):
                incident = None

            investigation = threat.get("investigation")
            if not isinstance(investigation, dict):
                investigation = None

            logger.info(
                (
                    "Starting on-demand user-security AI analysis | "
                    "SecurityID=%s | EventID=%s | Mode=%s"
                ),
                security_id,
                threat.get("event_id"),
                protection_mode,
            )

            result = shared_user_security_runtime_pipeline.process(
                threat=threat,
                protection_mode=protection_mode,
                incident=incident,
                investigation=investigation,
                enriched_evidence=None,
                graph_rag_context=None,
                additional_context={
                    "phase": "7D_ON_DEMAND_USER_SECURITY",
                    "runtime_source": "THREAT_DETAIL_ON_DEMAND",
                    "on_demand": True,
                    "security_id": security_id,
                },
            )

            snapshot = _snapshot_or_none(security_id)
            if snapshot is None:
                raise RuntimeError(
                    "AI pipeline completed without publishing a 7D.9 snapshot."
                )

            _set_job(
                security_id,
                state="READY",
                protection_mode=protection_mode,
                error=None,
                cached=False,
                completed_at=_now_iso(),
            )

            logger.info(
                (
                    "On-demand user-security AI analysis ready | "
                    "SecurityID=%s | Status=%s | Policy=%s"
                ),
                security_id,
                result.get("status"),
                result.get("policy_decision"),
            )

    except Exception as error:
        _set_job(
            security_id,
            state="FAILED",
            protection_mode=protection_mode,
            error=str(error),
            cached=False,
            completed_at=_now_iso(),
        )

        logger.exception(
            (
                "On-demand user-security AI analysis failed | "
                "SecurityID=%s | %s"
            ),
            security_id,
            error,
        )


# ================================================================
# ROUTER
# ================================================================


router = APIRouter(
    prefix="/api/v1/user-security",
    tags=["User Security AI Analysis"],
)


@router.post(
    "/threats/{security_id}/analyze",
    status_code=status.HTTP_202_ACCEPTED,
)
def analyze_user_security_threat(
    security_id: str,
    request: UserSecurityAnalyzeRequest,
):
    security_id = _safe_string(security_id)

    if not security_id:
        raise HTTPException(
            status_code=400,
            detail="security_id cannot be empty.",
        )

    protection_mode = (
        _safe_string(request.protection_mode)
        .upper()
        or "RECOMMENDED"
    )

    existing_snapshot = _snapshot_or_none(security_id)

    if existing_snapshot is not None and not request.force:
        current = _job_or_default(security_id)
        current["state"] = "READY"
        current["cached"] = True
        current["snapshot_available"] = True
        return current

    if _threat_resolver is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "User-security analysis is not ready because the "
                "canonical threat resolver has not been configured."
            ),
        )

    # Validate existence before creating a background thread so a bad ID
    # immediately returns 404 rather than a delayed FAILED job.
    try:
        target = _threat_resolver(security_id)
    except Exception as error:
        logger.exception(
            "Canonical threat lookup failed for on-demand analysis."
        )
        raise HTTPException(
            status_code=500,
            detail=f"Unable to resolve canonical threat: {error}",
        )

    if not isinstance(target, dict):
        raise HTTPException(
            status_code=404,
            detail=f"Canonical threat {security_id} was not found.",
        )

    with _jobs_lock:
        current = deepcopy(_jobs.get(security_id) or {})

        if current.get("state") in {"PENDING", "PROCESSING"}:
            current["snapshot_available"] = (
                existing_snapshot is not None
            )
            return current

        pending = _set_job(
            security_id,
            state="PENDING",
            protection_mode=protection_mode,
            error=None,
            cached=False,
            started_at=None,
            completed_at=None,
        )

    thread = threading.Thread(
        target=_run_analysis,
        kwargs={
            "security_id": security_id,
            "protection_mode": protection_mode,
        },
        name=f"SentinelXUserSecurity-{security_id}",
        daemon=True,
    )
    thread.start()

    pending["snapshot_available"] = existing_snapshot is not None
    return pending


@router.get(
    "/threats/{security_id}/analysis-status"
)
def get_user_security_analysis_status(
    security_id: str,
):
    security_id = _safe_string(security_id)

    if not security_id:
        raise HTTPException(
            status_code=400,
            detail="security_id cannot be empty.",
        )

    return _job_or_default(security_id)
