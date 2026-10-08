from typing import Any
from api.user_security_router import (
    router as user_security_router,
)
from api.user_security_analysis_router import (
    router as user_security_analysis_router,
    configure_user_security_analysis,
)

from api.security_contract import (
    SECURITY_CONTRACT_VERSION,
    build_canonical_security_object,
    build_canonical_incident_summary,
    build_canonical_investigation_contract,
    build_canonical_protection_preview_contract,
    validate_canonical_security_object,
)
from response.digital_twin_visual_preview import (
    DigitalTwinVisualPreview,
)
from datetime import datetime, timezone

import threading
from config import (
    ACTIVE_SOC_DATABASE_PATH,
    IS_VALIDATION_MODE,
)

from contextlib import asynccontextmanager

import json

import sqlite3

from pathlib import Path

from fastapi import FastAPI, HTTPException

from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field

from api.security_runtime_router import router as security_runtime_router

from response.persistent_soc_workflow import PersistentSOCWorkflow

from response.soc_ticket_store import SOCTicketStore

from response.incident_view_service import IncidentViewService

from response.soc_query_service import SOCQueryService

from response.backend_integrity_service import BackendIntegrityService

from detection.fusion.incident_store import IncidentStore

from endpoint.storage.database import get_endpoint_database_summary

from agents.multi_agent_pipeline import MultiAgentSecurityPipeline
from api.digital_twin_visual_router import build_digital_twin_visual_router

from endpoint.agent.sentinel_agent import SentinelAgent

from endpoint.agent.telemetry_manager import shared_telemetry_manager

from endpoint.utils.logger import get_logger

from endpoint.storage.database import initialize_database

# Inside your existing FastAPI lifespan,

# before starting SentinelAgent:

initialize_database()

logger = get_logger(__name__)

sentinel_agent = None

sentinel_agent_thread = None

sentinel_agent_lock = threading.RLock()

# ================================================================

# SENTINEL AGENT

# ================================================================

def run_sentinel_agent():

    global sentinel_agent

    try:

        logger.info(

            "Starting SENTINEL-X Endpoint Agent from FastAPI runtime."

        )

        if sentinel_agent is None:

            logger.error("SentinelAgent instance is unavailable.")

            return

        sentinel_agent.start()

    except Exception as error:

        logger.exception(

            "SENTINEL-X Endpoint Agent background runtime failed | %s",

            error,

        )

    finally:

        logger.info(

            "SENTINEL-X Endpoint Agent background thread exited."

        )
        
# ================================================================
# FASTAPI LIFESPAN
# ================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    global sentinel_agent
    global sentinel_agent_thread

    logger.info("=" * 78)
    logger.info(
        "Starting SENTINEL-X backend runtime..."
    )

    # ============================================================
    # ENDPOINT COLLECTION RUNTIME
    #
    # HYBRID VALIDATION MODE
    # ----------------------
    #
    # VALIDATION keeps the synthetic product database active,
    # while real endpoint collectors are allowed to run so that
    # Live Monitor can continuously observe the current PC.
    #
    # TelemetryManager.emit() provides the isolation boundary:
    #
    # VALIDATION + REAL COLLECTOR EVENT
    #
    #       Collector
    #           ↓
    #       SecurityEvent
    #           ↓
    #       runtime memory
    #           ↓
    #       /telemetry/live
    #           ↓
    #       Live Monitor
    #
    # It must NOT continue to:
    #
    #       save_event()
    #       provenance graph
    #       correlation
    #       incidents
    #
    # Synthetic validation data continues using:
    #
    #       sentinel_validation.db
    #
    # LIVE mode later enables the complete endpoint pipeline.
    # ============================================================

    if IS_VALIDATION_MODE:

        logger.info(
            "SENTINEL-X HYBRID VALIDATION mode active."
        )

        logger.info(
            (
                "Synthetic validation persistence "
                "remains active at: %s"
            ),
            ACTIVE_SOC_DATABASE_PATH,
        )

        logger.info(
            (
                "Real endpoint collectors are ENABLED "
                "for Live Monitor runtime telemetry only."
            )
        )

        logger.info(
            (
                "Real collector events will NOT be "
                "persisted, correlated, or promoted "
                "to incidents in VALIDATION."
            )
        )

    else:

        logger.info(
            "SENTINEL-X LIVE mode active."
        )

        logger.info(
            (
                "Full endpoint telemetry persistence "
                "and correlation are enabled."
            )
        )

    # ============================================================
    # START SENTINEL AGENT
    #
    # IMPORTANT:
    #
    # The agent now starts in BOTH:
    #
    #       VALIDATION
    #       LIVE
    #
    # The difference between the two modes is controlled by the
    # telemetry/detection pipeline, NOT by disabling collectors.
    # ============================================================

    with sentinel_agent_lock:

        existing_thread_alive = (

            sentinel_agent_thread
            is not None

            and

            sentinel_agent_thread.is_alive()

        )

        if not existing_thread_alive:

            # ----------------------------------------------------
            # CREATE ENDPOINT AGENT
            # ----------------------------------------------------

            sentinel_agent = (
                SentinelAgent()
            )

            # ----------------------------------------------------
            # RUN AGENT OUTSIDE FASTAPI EVENT LOOP
            #
            # SentinelAgent owns several long-running collector
            # loops, so it belongs in a daemon background thread.
            # ----------------------------------------------------

            sentinel_agent_thread = (
                threading.Thread(

                    target=
                        run_sentinel_agent,

                    name=
                        "SentinelXEndpointAgent",

                    daemon=
                        True,
                )
            )

            sentinel_agent_thread.start()

            logger.info(
                (
                    "SENTINEL-X Endpoint Agent "
                    "background thread started."
                )
            )

        else:

            logger.warning(
                (
                    "SENTINEL-X Endpoint Agent "
                    "is already running."
                )
            )

    # ============================================================
    # APPLICATION STATE
    #
    # Expose the running objects to FastAPI routes.
    # ============================================================

    app.state.sentinel_agent = (
        sentinel_agent
    )

    app.state.telemetry_manager = (
        shared_telemetry_manager
    )

    logger.info(
        "SENTINEL-X FastAPI runtime started."
    )

    logger.info(
        "=" * 78
    )

    # ============================================================
    # APPLICATION RUNNING
    # ============================================================

    try:

        yield

    # ============================================================
    # SHUTDOWN
    # ============================================================

    finally:

        logger.info(
            "=" * 78
        )

        logger.info(
            "Stopping SENTINEL-X backend runtime..."
        )

        # ========================================================
        # STOP SENTINEL AGENT
        # ========================================================

        with sentinel_agent_lock:

            if sentinel_agent is not None:

                try:

                    sentinel_agent.stop()

                except Exception as error:

                    logger.exception(
                        (
                            "Unable to stop "
                            "SentinelAgent cleanly | %s"
                        ),
                        error,
                    )

            # ----------------------------------------------------
            # WAIT BRIEFLY FOR COLLECTOR THREAD
            # ----------------------------------------------------

            if (

                sentinel_agent_thread
                is not None

                and

                sentinel_agent_thread.is_alive()

            ):

                sentinel_agent_thread.join(
                    timeout=10
                )

        logger.info(
            "SENTINEL-X backend runtime stopped."
        )

        logger.info(
            "=" * 78
        )
# ================================================================

# APPLICATION

# ================================================================

app = FastAPI(

    title="SENTINEL-X SOC API",

    description=(

        "Persistent backend API for SENTINEL-X "

        "Autonomous Multi-Agent Cybersecurity Defense "

        "and Incident Intelligence Platform."

    ),

    version="1.4.0",

    lifespan=lifespan,

)

app.include_router(security_runtime_router)

app.include_router(user_security_router)
app.include_router(user_security_analysis_router)
app.add_middleware(

    CORSMiddleware,

    allow_origins=[

        "http://localhost:5173",

        "http://127.0.0.1:5173",

        "http://localhost:5174",

        "http://127.0.0.1:5174",

        "http://localhost:5175",

        "http://127.0.0.1:5175",

    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

)

# ================================================================

# SHARED SERVICES

# ================================================================

workflow = PersistentSOCWorkflow(simulation_mode=True)

detected_incident_store = IncidentStore()

multi_agent_pipeline = MultiAgentSecurityPipeline(

    autonomy_level=2

)
canonical_protection_preview_engine = (
    DigitalTwinVisualPreview()
)

app.include_router(
    build_digital_twin_visual_router(
        detected_incident_store,
        multi_agent_pipeline,

        incident_hydrator=(
            lambda incident:
                _hydrate_incident_for_analysis(
                    incident
                )
        ),
    )
)

ticket_store = SOCTicketStore()

incident_view_service = IncidentViewService(

    workflow=workflow,

    ticket_store=ticket_store,

)

query_service = SOCQueryService(

    case_store=workflow.case_store,

    ticket_store=ticket_store,

    action_store=workflow.action_store,

)

integrity_service = BackendIntegrityService(

    case_store=workflow.case_store,

    ticket_store=ticket_store,

    action_store=workflow.action_store,

    evidence_store=workflow.evidence_store,

)

# ================================================================

# REQUEST MODELS

# ================================================================

class CreateCaseRequest(BaseModel):

    incident_id: str = Field(..., min_length=1)

    intelligence: dict

class AnalystDecisionRequest(BaseModel):

    analyst: str = Field(..., min_length=1)

    comment: str = ""

class AnalystRejectionRequest(BaseModel):

    analyst: str = Field(..., min_length=1)

    reason: str = Field(..., min_length=1)

class MitigationVerificationRequest(BaseModel):

    before_state: dict

    simulated_after_state: dict

    response_result: dict

# ================================================================

# HELPERS

# ================================================================

def now_iso():

    return datetime.now(timezone.utc).isoformat()

def enrich_detected_incident(incident: dict):

    if not isinstance(incident, dict):

        return {}

    incident_id = incident.get("incident_id")

    soc_case = None

    if incident_id:

        try:

            soc_case = workflow.recover_case(incident_id)

        except Exception:

            soc_case = None

    soc_case_exists = soc_case is not None

    soc_case_status = None

    approval_status = None

    ticket_id = None

    ticket_priority = None

    selected_plan = None

    residual_risk = None

    mitigation_status = "NOT_VERIFIED"

    if soc_case_exists:

        soc_case_status = soc_case.get("status")

        ticket_data = soc_case.get("ticket_data") or {}

        if isinstance(ticket_data, dict):

            approval_status = ticket_data.get("approval_status")

            ticket_id = ticket_data.get("ticket_id")

            ticket_priority = ticket_data.get("priority")

        decision = soc_case.get("decision") or {}

        if isinstance(decision, dict):

            selected_plan = (

                decision.get("selected_plan_name")

                or decision.get("selected_plan")

                or decision.get("plan_name")

            )

            residual_risk = (

                decision.get("predicted_residual_risk")

                or decision.get("residual_risk")

            )

        mitigation = soc_case.get("mitigation_verification") or {}

        if isinstance(mitigation, dict):

            mitigation_status = (

                mitigation.get("status")

                or "NOT_VERIFIED"

            )

    return {

        **incident,

        "record_type": "DETECTED_INCIDENT",

        "soc_case_exists": soc_case_exists,

        "soc_case_status": soc_case_status,

        "approval_status": approval_status,

        "ticket_id": ticket_id,

        "ticket_priority": ticket_priority,

        "selected_plan": selected_plan,

        "residual_risk": residual_risk,

        "mitigation_status": mitigation_status,

        "simulation_mode": True,

        "real_response_executed": False,

    }

def serialize_value(value: Any):

    if value is None:

        return None

    if isinstance(value, (str, int, float, bool)):

        return value

    if isinstance(value, dict):

        return {

            str(key): serialize_value(item)

            for key, item in value.items()

        }

    if isinstance(value, (list, tuple, set)):

        return [

            serialize_value(item)

            for item in value

        ]

    if hasattr(value, "to_dict"):

        return serialize_value(value.to_dict())

    return str(value)

def require_case(incident_id: str):

    case = workflow.recover_case(incident_id)

    if case is None:

        raise HTTPException(

            status_code=404,

            detail=f"SOC case not found for incident {incident_id}.",

        )

    return case

# ================================================================

# ROOT

# ================================================================

@app.get("/")

def root():

    return {

        "product": "SENTINEL-X",

        "service": "Persistent SOC Backend API",

        "version": "1.4.0",

        "status": "RUNNING",

        "simulation_mode": True,

        "persistent_recovery": True,

        "evidence_persistence": True,

        "timeline_persistence": True,

        "soc_query_layer": True,

        "backend_integrity": True,

        "real_response_execution": False,

    }

# ================================================================

# HEALTH

# ================================================================

@app.get("/api/v1/health")

def health():

    return {

        "status": "HEALTHY",

        "service": "SENTINEL-X SOC API",

        "version": "1.4.0",

        "timestamp": now_iso(),

        "simulation_mode": True,

        "persistent_recovery": True,

        "evidence_persistence": True,

        "timeline_persistence": True,

        "soc_query_layer": True,

        "backend_integrity": True,

        "real_response_execution": False,

    }

# ================================================================

# LIVE TELEMETRY

# ================================================================

@app.get("/api/v1/telemetry/live")

def get_live_telemetry():

    try:

        manager = shared_telemetry_manager

        snapshot = manager.get_live_snapshot(

            reset_interval=False

        )

        agent = sentinel_agent

        agent_running = bool(

            agent is not None

            and agent.running

        )

        collectors = {

            "process": False,

            "file": False,

            "network": False,

            "registry": False,


            "auth": False,

        }

        if agent is not None:

            threads = dict(

                getattr(agent, "collector_threads", {}) or {}

            )

            for name, thread in threads.items():

                if name in collectors:

                    collectors[name] = bool(

                        thread is not None

                        and thread.is_alive()

                    )

        healthy_count = sum(collectors.values())

        all_healthy = (

            agent_running

            and healthy_count == len(collectors)

        )

        runtime_counts = (

            snapshot.get("runtime_counts") or {}

        )

        recent = (

            snapshot.get("recent") or {}

        )

        return {

            **snapshot,

            "status": (

                "ACTIVE"

                if all_healthy

                else "DEGRADED"

                if agent_running

                else "OFFLINE"

            ),

            "running": agent_running,

            "agent_running": agent_running,

            "total": snapshot.get(

                "total",

                snapshot.get("runtime_event_count", 0),

            ),

            "runtime_event_count": snapshot.get(

                "runtime_event_count",

                snapshot.get("total", 0),

            ),

            "runtime_counts": runtime_counts,

            "recent": recent,

            "collectors": collectors,

            "healthy_collector_count": healthy_count,

            "expected_collector_count": len(collectors),

            "all_collectors_healthy": all_healthy,

            "collection_mode": "CONTINUOUS",

            "simulation_mode": True,

            "real_response_execution": False,

        }

    except Exception:

        logger.exception("Live telemetry endpoint failed")

        raise HTTPException(

            status_code=500,

            detail="Unable to retrieve live telemetry.",

        )

# ================================================================

# DETECTION EVENT ENRICHMENT HELPERS

# ================================================================

def _safe_json_dict(value):

    """

    Convert a JSON database value into a dictionary.

    This helper is intentionally defensive because historical

    endpoint records may contain NULL, malformed JSON, or already

    decoded dictionaries.

    """

    if isinstance(value, dict):

        return value

    if not value:

        return {}

    try:

        parsed = json.loads(value)

        if isinstance(parsed, dict):

            return parsed

    except (

        TypeError,

        ValueError,

        json.JSONDecodeError,

    ):

        pass

    return {}

def _get_endpoint_database_path() -> Path:
    """
    Return the database associated with the current
    SENTINEL-X runtime mode.

    VALIDATION:
        sentinel_validation.db

    LIVE:
        sentinel_endpoint.db
    """

    return Path(
        ACTIVE_SOC_DATABASE_PATH
    )
def _load_event_context_by_event_ids(

    event_ids,

):

    """

    Read already-persisted endpoint events for the requested

    detection event IDs.

    IMPORTANT:

    - Read-only SQLite connection.

    - Does not run collectors.

    - Does not run models.

    - Does not create detections.

    - Does not modify incidents.

    """

    clean_event_ids = [

        str(event_id)

        for event_id in event_ids

        if event_id

    ]

    if not clean_event_ids:

        return {}

    database_path = (

        _get_endpoint_database_path()

    )

    if not database_path.exists():

        logger.warning(

            "Endpoint database not found for "

            "detection enrichment | Path=%s",

            database_path,

        )

        return {}

    placeholders = ",".join(

        "?"

        for _ in clean_event_ids

    )

    query = f"""

        SELECT

            event_id,

            timestamp,

            device_id,

            event_type,

            severity,

            source,

            process_data,

            file_data,

            network_data,

            registry_data,

            metadata

        FROM events

        WHERE event_id IN ({placeholders})

    """

    connection = None

    try:

        connection = sqlite3.connect(

            database_path.as_uri()

            + "?mode=ro",

            uri=True,

        )

        connection.row_factory = (

            sqlite3.Row

        )

        rows = connection.execute(

            query,

            clean_event_ids,

        ).fetchall()

        result = {}

        for row in rows:

            result[

                str(row["event_id"])

            ] = dict(row)

        return result

    except Exception:

        logger.exception(

            "Unable to enrich detections "

            "with endpoint event evidence"

        )

        return {}

    finally:

        if connection is not None:

            connection.close()


def _safe_json_value(value, default=None):
    """Decode a JSON database value while preserving scalars."""

    if value is None:
        return default

    if isinstance(value, (dict, list, int, float, bool)):
        return value

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return default

        try:
            return json.loads(stripped)
        except (TypeError, ValueError, json.JSONDecodeError):
            return value

    return default


def _first_present(*values):
    for value in values:
        if value is not None:
            return value
    return None


def _severity_rank(value) -> int:
    return {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(str(value or "INFO").upper(), 0)


def _infer_analysis_category(event_type, metadata):
    metadata = metadata if isinstance(metadata, dict) else {}

    category = str(
        metadata.get("event_category") or ""
    ).upper()

    if category in {"PROCESS", "NETWORK", "FILE", "REGISTRY"}:
        return category

    event_type = str(event_type or "").lower()

    if event_type.startswith("process"):
        return "PROCESS"
    if event_type.startswith("network"):
        return "NETWORK"
    if event_type.startswith("file"):
        return "FILE"
    if event_type.startswith(("registry", "startup")):
        return "REGISTRY"

    return "OTHER"


def _load_detection_context_by_event_ids(event_ids):
    """Read persisted detection rows linked to an incident's events."""

    clean_event_ids = [
        str(event_id)
        for event_id in event_ids
        if event_id
    ]

    if not clean_event_ids:
        return []

    database_path = _get_endpoint_database_path()

    if not database_path.exists():
        return []

    placeholders = ",".join("?" for _ in clean_event_ids)

    query = f"""
        SELECT
            id AS detection_id,
            event_id,
            engine,
            detected,
            threat_type,
            confidence,
            risk_score,
            severity,
            reason,
            created_at
        FROM detections
        WHERE event_id IN ({placeholders})
        ORDER BY id ASC
    """

    connection = None

    try:
        connection = sqlite3.connect(
            database_path.as_uri() + "?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row

        return [
            dict(row)
            for row in connection.execute(
                query,
                clean_event_ids,
            ).fetchall()
        ]

    except Exception:
        logger.exception(
            "Unable to load incident-linked detection evidence"
        )
        return []

    finally:
        if connection is not None:
            connection.close()


def _score_from_model_block(block, *keys):
    if not isinstance(block, dict):
        return None

    for key in keys:
        value = block.get(key)
        if value is not None:
            return value

    return None


def _hydrate_incident_for_analysis(incident: dict) -> dict:
    """
    Build the analysis contract consumed by the multi-agent pipeline.

    The correlation incident store intentionally remains lightweight.
    Before AI analysis, this helper joins it back to the persisted raw
    events and detections so the agents receive the detector output that
    actually caused the incident.

    VALIDATION mode may use a clearly-labelled fallback device identity
    so deterministic synthetic telemetry can exercise the SOC workflow.
    It never makes validation evidence production eligible.
    """

    if not isinstance(incident, dict):
        return {}

    hydrated = dict(incident)

    raw_timeline = [
        dict(item)
        for item in (incident.get("timeline") or [])
        if isinstance(item, dict)
    ]

    ordered_event_ids = []
    seen_event_ids = set()

    for event in raw_timeline:
        event_id = str(event.get("event_id") or "").strip()
        if event_id and event_id not in seen_event_ids:
            seen_event_ids.add(event_id)
            ordered_event_ids.append(event_id)

    for event_id in incident.get("event_ids") or []:
        event_id = str(event_id or "").strip()
        if event_id and event_id not in seen_event_ids:
            seen_event_ids.add(event_id)
            ordered_event_ids.append(event_id)

    persisted_events = _load_event_context_by_event_ids(
        ordered_event_ids
    )

    validation_device = "SENTINEL-X-VALIDATION-ENDPOINT"
    hydrated_timeline = []
    raw_by_id = {
        str(item.get("event_id")): item
        for item in raw_timeline
        if item.get("event_id")
    }

    for event_id in ordered_event_ids:
        existing = dict(raw_by_id.get(event_id) or {})
        row = persisted_events.get(event_id)

        if row:
            metadata = _safe_json_dict(row.get("metadata"))
            process = _safe_json_dict(row.get("process_data"))
            file_data = _safe_json_dict(row.get("file_data"))
            network = _safe_json_dict(row.get("network_data"))
            registry = _safe_json_dict(row.get("registry_data"))

            device_id = (
                row.get("device_id")
                or existing.get("device_id")
                or metadata.get("device_id")
            )

            if IS_VALIDATION_MODE and not device_id:
                device_id = validation_device
                metadata = dict(metadata)
                metadata["device_id"] = device_id
                metadata["device_identity_source"] = (
                    "VALIDATION_FALLBACK"
                )

            if IS_VALIDATION_MODE:
                metadata = dict(metadata)
                metadata["validation_mode"] = True
                metadata["synthetic"] = True

            event_type = row.get("event_type") or existing.get("event_type")

            merged = {
                **existing,
                "event_id": event_id,
                "timestamp": row.get("timestamp") or existing.get("timestamp"),
                "device_id": device_id,
                "event_type": event_type,
                "severity": row.get("severity") or existing.get("severity") or "INFO",
                "source": row.get("source") or existing.get("source"),
                "process": process,
                "file": file_data,
                "network": network,
                "registry": registry,
                "metadata": metadata,
                "event_category": _infer_analysis_category(
                    event_type,
                    metadata,
                ),
                "simulation_mode": bool(IS_VALIDATION_MODE),
            }
        else:
            merged = existing

            if IS_VALIDATION_MODE:
                metadata = _safe_json_dict(merged.get("metadata"))
                metadata = dict(metadata)
                metadata["validation_mode"] = True
                metadata["synthetic"] = True

                if not merged.get("device_id"):
                    merged["device_id"] = validation_device
                    metadata["device_id"] = validation_device
                    metadata["device_identity_source"] = (
                        "VALIDATION_FALLBACK"
                    )

                merged["metadata"] = metadata
                merged["simulation_mode"] = True

        hydrated_timeline.append(merged)

    detection_rows = _load_detection_context_by_event_ids(
        ordered_event_ids
    )

    detections = []

    for row in detection_rows:
        if not bool(row.get("detected")):
            continue

        event_id = str(row.get("event_id") or "")
        event_row = persisted_events.get(event_id)
        event_evidence = _build_detection_evidence(event_row)

        process_evidence = event_evidence.get("process") or {}
        model_scores = event_evidence.get("model_scores") or {}
        raw_process = (
            _safe_json_dict(event_row.get("process_data"))
            if event_row
            else {}
        )

        temporal_block = _first_present(
            raw_process.get("temporal_ai"),
            raw_process.get("temporal"),
            raw_process.get("temporal_result"),
        )
        if not isinstance(temporal_block, dict):
            temporal_block = {}

        isolation_block = process_evidence.get("isolation_forest")
        if not isinstance(isolation_block, dict):
            isolation_block = {}

        autoencoder_block = process_evidence.get("autoencoder")
        if not isinstance(autoencoder_block, dict):
            autoencoder_block = {}

        rule_score = _first_present(
            model_scores.get("rule_score"),
            raw_process.get("rule_score"),
            raw_process.get("behavior_score"),
        )
        statistical_score = _first_present(
            model_scores.get("statistical_score"),
            raw_process.get("statistical_score"),
        )
        temporal_score = _first_present(
            raw_process.get("temporal_score"),
            raw_process.get("temporal_ai_score"),
            _score_from_model_block(
                temporal_block,
                "score",
                "temporal_score",
                "anomaly_score",
                "confidence",
            ),
        )
        isolation_score = _first_present(
            model_scores.get("isolation_forest_score"),
            _score_from_model_block(
                isolation_block,
                "anomaly_confidence",
                "score",
                "confidence",
            ),
        )
        autoencoder_score = _first_present(
            model_scores.get("autoencoder_score"),
            _score_from_model_block(
                autoencoder_block,
                "anomaly_confidence",
                "score",
                "confidence",
            ),
        )
        fusion_score = _first_present(
            model_scores.get("fusion_score"),
            process_evidence.get("fusion_score"),
            row.get("risk_score"),
        )

        stored_reason = _safe_json_value(
            row.get("reason"),
            [],
        )
        if isinstance(stored_reason, str):
            stored_reason = [stored_reason]
        if not isinstance(stored_reason, list):
            stored_reason = []

        fusion_reasons = process_evidence.get("fusion_reasons") or []
        if isinstance(fusion_reasons, str):
            fusion_reasons = [fusion_reasons]
        if not isinstance(fusion_reasons, list):
            fusion_reasons = []

        all_reasons = []
        for value in [*fusion_reasons, *stored_reason]:
            text_value = str(value or "").strip()
            if text_value and text_value not in all_reasons:
                all_reasons.append(text_value)

        reason_text = " ".join(all_reasons).upper()
        supporting_signals = []

        def add_signal(name):
            if name not in supporting_signals:
                supporting_signals.append(name)

        try:
            if float(rule_score or 0) >= 35:
                add_signal("rules")
        except (TypeError, ValueError):
            pass

        if "RULE" in reason_text:
            add_signal("rules")

        try:
            if float(temporal_score or 0) >= 60:
                add_signal("temporal_ai")
        except (TypeError, ValueError):
            pass

        if "TEMPORAL" in reason_text:
            add_signal("temporal_ai")

        try:
            if float(statistical_score or 0) >= 35:
                add_signal("statistical")
        except (TypeError, ValueError):
            pass

        if "STATISTICAL" in reason_text:
            add_signal("statistical")

        try:
            if float(isolation_score or 0) >= 60:
                add_signal("isolation_forest")
        except (TypeError, ValueError):
            pass

        try:
            if float(autoencoder_score or 0) >= 60:
                add_signal("autoencoder")
        except (TypeError, ValueError):
            pass

        detections.append({
            "detection_id": row.get("detection_id"),
            "event_id": event_id,
            "stored_detection_record": True,
            "detected": True,
            "engine": row.get("engine"),
            "threat_type": row.get("threat_type"),
            "confidence": row.get("confidence"),
            "risk_score": row.get("risk_score"),
            "severity": row.get("severity") or "INFO",
            "reason": stored_reason,
            "created_at": row.get("created_at"),
            "device_id": (
                (event_evidence.get("event") or {}).get("device_id")
                or (validation_device if IS_VALIDATION_MODE else None)
            ),
            "process_name": process_evidence.get("process_name"),
            "pid": process_evidence.get("pid"),
            "ppid": process_evidence.get("ppid"),
            "parent_process_name": process_evidence.get("parent_process_name"),
            "rule_score": rule_score,
            "statistical_score": statistical_score,
            "isolation_forest_score": isolation_score,
            "autoencoder_score": autoencoder_score,
            "temporal_score": temporal_score,
            "fusion_score": fusion_score,
            "fusion_reasons": all_reasons,
            "supporting_signals": supporting_signals,
            "independent_signal_count": len(supporting_signals),
            "validation_only": bool(IS_VALIDATION_MODE),
            "production_eligible": not bool(IS_VALIDATION_MODE),
        })

    original_severity = str(
        hydrated.get("severity") or "INFO"
    ).upper()

    analysis_severity = original_severity
    for detection in detections:
        candidate = str(
            detection.get("severity") or "INFO"
        ).upper()
        if _severity_rank(candidate) > _severity_rank(analysis_severity):
            analysis_severity = candidate

    hydrated["stored_incident_severity"] = original_severity
    hydrated["analysis_severity"] = analysis_severity
    hydrated["severity"] = analysis_severity
    hydrated["timeline"] = hydrated_timeline
    hydrated["event_ids"] = ordered_event_ids
    hydrated["event_count"] = len(hydrated_timeline)
    hydrated["detections"] = detections
    hydrated["analysis_context"] = {
        "runtime_mode": (
            "VALIDATION" if IS_VALIDATION_MODE else "LIVE"
        ),
        "validation_mode": bool(IS_VALIDATION_MODE),
        "validation_only": bool(IS_VALIDATION_MODE),
        "synthetic_evidence_allowed": bool(IS_VALIDATION_MODE),
        "production_eligible": not bool(IS_VALIDATION_MODE),
        "real_response_execution_allowed": False,
    }

    return hydrated


def _build_detection_evidence(
    event_record,
):
    """Convert a persisted endpoint event into frontend-safe evidence."""

    if not event_record:
        return {"event_found": False}

    process_data = _safe_json_dict(
        event_record.get("process_data")
    )
    file_data = _safe_json_dict(
        event_record.get("file_data")
    )
    network_data = _safe_json_dict(
        event_record.get("network_data")
    )
    registry_data = _safe_json_dict(
        event_record.get("registry_data")
    )
    metadata = _safe_json_dict(
        event_record.get("metadata")
    )

    process_name = (
        process_data.get("name")
        or process_data.get("process_name")
    )
    parent_process_name = (
        process_data.get("parent_name")
        or process_data.get("parent_process_name")
    )

    process_evidence = {
        "pid": process_data.get("pid"),
        "ppid": process_data.get("ppid"),
        "process_name": process_name,
        "parent_process_name": parent_process_name,
        "create_time": process_data.get("create_time"),
        "cpu_percent": process_data.get("cpu_percent"),
        "memory_percent": process_data.get("memory_percent"),
        "rss_mb": process_data.get("rss_mb"),
        "num_threads": process_data.get("num_threads"),
        "num_handles": process_data.get("num_handles"),
        "fusion_version": process_data.get("fusion_version"),
        "fusion_score": process_data.get("fusion_score"),
        "fusion_severity": process_data.get("fusion_severity"),
        "fusion_confidence": process_data.get("fusion_confidence"),
        "fusion_reasons": process_data.get("fusion_reasons"),
        "ai_consensus_score": process_data.get("ai_consensus_score"),
        "ai_consensus": process_data.get("ai_consensus"),
        "isolation_forest": process_data.get("isolation_forest"),
        "autoencoder": process_data.get("autoencoder"),
        "temporal_ai": (
            process_data.get("temporal_ai")
            or process_data.get("temporal")
            or process_data.get("temporal_result")
        ),
        "ai_behavior_context": process_data.get("ai_behavior_context"),
    }

    isolation = process_evidence.get("isolation_forest")
    if not isinstance(isolation, dict):
        isolation = {}

    autoencoder = process_evidence.get("autoencoder")
    if not isinstance(autoencoder, dict):
        autoencoder = {}

    temporal = process_evidence.get("temporal_ai")
    if not isinstance(temporal, dict):
        temporal = {}

    model_scores = {
        "rule_score": _first_present(
            metadata.get("rule_score"),
            process_data.get("rule_score"),
            process_data.get("behavior_score"),
        ),
        "statistical_score": _first_present(
            metadata.get("statistical_score"),
            process_data.get("statistical_score"),
        ),
        "isolation_forest_score": _first_present(
            metadata.get("isolation_forest_score"),
            isolation.get("anomaly_confidence"),
            isolation.get("score"),
        ),
        "autoencoder_score": _first_present(
            metadata.get("autoencoder_score"),
            autoencoder.get("anomaly_confidence"),
            autoencoder.get("score"),
        ),
        "temporal_score": _first_present(
            metadata.get("temporal_score"),
            process_data.get("temporal_score"),
            process_data.get("temporal_ai_score"),
            temporal.get("score"),
            temporal.get("temporal_score"),
            temporal.get("anomaly_score"),
        ),
        "ai_consensus_score": _first_present(
            metadata.get("ai_consensus_score"),
            process_data.get("ai_consensus_score"),
        ),
        "ai_agreement": metadata.get("ai_agreement"),
        "ai_disagreement": metadata.get("ai_disagreement"),
        "fusion_score": _first_present(
            metadata.get("fusion_score"),
            process_data.get("fusion_score"),
        ),
        "evidence_confidence": metadata.get("evidence_confidence"),
        "critical_allowed": metadata.get("critical_allowed"),
        "feature_record_id": metadata.get("feature_record_id"),
        "event_category": metadata.get("event_category"),
    }

    return {
        "event_found": True,

        "event": {
            "timestamp": event_record.get("timestamp"),
            "device_id": event_record.get("device_id"),
            "event_type": event_record.get("event_type"),
            "severity": event_record.get("severity"),
            "source": event_record.get("source"),
        },

        "process": process_evidence,

        "model_scores": model_scores,

        "file": file_data,

        "network": network_data,

        "registry": registry_data,

        # NEW
        # Needed for authentication, startup and system evidence.
        "metadata": metadata,
    }

# ================================================================

# RECENT SECURITY DETECTIONS

# ================================================================

@app.get("/api/v1/telemetry/detections")
def get_live_detections(limit: int = 50):
    """Return recent persisted detections with read-only event evidence."""
    limit = max(1, min(limit, 100))

    try:
        summary = get_endpoint_database_summary(recent_limit=limit) or {}
        records = summary.get("detections") or []
        if not isinstance(records, list):
            records = []

        event_ids = [
            record.get("event_id")
            for record in records
            if isinstance(record, dict)
            and record.get("detected") is not False
            and record.get("event_id")
        ]
        event_context = _load_event_context_by_event_ids(event_ids)
        detections = []

        for record in records:
            if not isinstance(record, dict) or record.get("detected") is False:
                continue

            event_id = record.get("event_id")
            persisted_event = event_context.get(str(event_id)) if event_id else None
            evidence = _build_detection_evidence(persisted_event)
            event_fields = evidence.get("event") or {}

            process = evidence.get("process") or {}
            network = evidence.get("network") or {}

            threat_type = record.get("threat_type")
            event_type = event_fields.get("event_type")

            # Network alerts can carry their process identity
            # inside network_data rather than process_data.
            is_network_alert = (
                event_type == "network_behavior_alert"
                and record.get("engine") == "network_behavior"
            )

            process_name = (
                process.get("process_name")
                or (
                    network.get("process_name")
                    if is_network_alert
                    else None
                )
            )

            pid = (
                process.get("pid")
                if process.get("pid") is not None
                else (
                    network.get("pid")
                    if is_network_alert
                    else None
                )
            )

            # ============================================================
            # EVIDENCE-GROUNDED DISPLAY TITLE
            # ============================================================

            if is_network_alert:

                category = str(
                    threat_type or "NETWORK_BEHAVIOR"
                ).replace("_", " ").title()

                if process_name:
                    display_title = f"{category} - {process_name}"
                else:
                    display_title = category

            else:
    
                category = str(
                    threat_type
                    or "SECURITY_DETECTION"
                ).replace(
                    "_",
                    " ",
                ).title()


                if process_name:

                    display_title = (
                        f"{category} - "
                        f"{process_name}"
                    )

                else:

                    display_title = (
                        category
                    )

            detections.append({
                # Preserve all previous frontend response keys.
                "detection_id": record.get("detection_id", record.get("id")),
                "event_id": event_id,
                "detected":
                    record.get(
                        "detected",
                        True,
                    ),
                "timestamp": (
                    event_fields.get("timestamp")
                    or record.get("timestamp")
                    or record.get("detected_at")
                    or record.get("created_at")
                ),
                "source": (
                    record.get("source")
                    or record.get("event_type")
                    or record.get("category")
                    or event_fields.get("source")
                ),
                "engine": record.get("engine"),
                "threat_type": threat_type,
                "severity": record.get("severity"),
                "confidence": record.get("confidence"),
                "risk_score": record.get("risk_score"),
                "incident_id": record.get("incident_id"),
                # Event-linked explanation fields.
                "display_title": display_title,
                "detection_reason": record.get("reason"),
                "event_type": event_type,
                "device_id": event_fields.get("device_id"),
                "process_name": process_name,
                "pid": pid,
                "ppid": process.get("ppid"),
                "parent_process_name": process.get("parent_process_name"),
                "process_evidence": process,
                "model_scores": evidence.get("model_scores") or {},
                "file_evidence": evidence.get("file") or {},
                "network_evidence": evidence.get("network") or {},
                "registry_evidence": evidence.get("registry") or {},
                "event_metadata": evidence.get("metadata") or {},
                "event_evidence_available": bool(evidence.get("event_found")),
            })

        return {
            "status": "ACTIVE",
            "timestamp": now_iso(),
            "count": len(detections),
            "total_stored_detections": summary.get("detection_count", 0),
            "detections": detections,
            "simulation_mode": True,
            "real_response_execution": False,
        }

    except Exception:
        logger.exception("Failed to retrieve recent detections")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve security detections.",
        )


# ================================================================
# CANONICAL USER SECURITY API HELPERS
# ================================================================

def _canonical_incident_sort_key(
    incident,
):
    """
    Deterministically choose the most representative incident
    for a detection.

    Preference:
        1. larger correlated event set
        2. higher correlation score
        3. stable incident id
    """

    if not isinstance(
        incident,
        dict,
    ):

        return (
            0,
            0,
            "",
        )

    try:

        event_count = int(
            incident.get(
                "event_count",
                0,
            )
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):

        event_count = 0

    try:

        correlation_score = float(
            incident.get(
                "correlation_score",
                0,
            )
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):

        correlation_score = 0.0

    incident_id = str(
        incident.get(
            "incident_id"
        )
        or ""
    )

    return (
        event_count,
        correlation_score,
        incident_id,
    )


def _build_event_incident_index(
    incidents,
):
    """
    Build:

        event_id
            ↓
        [incident, incident, ...]

    Internal workflow regression incidents are harmless here
    because canonical visibility will filter them later.
    """

    index = {}

    for incident in incidents:

        if not isinstance(
            incident,
            dict,
        ):

            continue

        event_ids = (
            incident.get(
                "event_ids"
            )
            or []
        )

        if not isinstance(
            event_ids,
            list,
        ):

            continue

        for event_id in event_ids:

            key = str(
                event_id
                or ""
            ).strip()

            if not key:

                continue

            index.setdefault(
                key,
                [],
            ).append(
                incident
            )

    return index


def _canonical_security_threats(
    *,
    limit=100,
    include_internal=False,
):
    """
    Build canonical user-facing security objects from the
    existing detection + correlation stores.

    Does not modify persistence.
    Does not perform investigation.
    Does not run the Digital Twin.
    """

    limit = max(
        1,
        min(
            int(limit),
            100,
        ),
    )

    # ------------------------------------------------------------
    # EXISTING ENRICHED DETECTIONS
    # ------------------------------------------------------------

    detection_payload = (
        get_live_detections(
            limit=limit
        )
        or {}
    )

    detections = (
        detection_payload.get(
            "detections"
        )
        or []
    )

    if not isinstance(
        detections,
        list,
    ):

        detections = []

    # ------------------------------------------------------------
    # EXISTING CORRELATED INCIDENTS
    # ------------------------------------------------------------

    incidents = (
        detected_incident_store
        .get_incidents()
        or []
    )

    if not isinstance(
        incidents,
        list,
    ):

        incidents = []

    event_incident_index = (
        _build_event_incident_index(
            incidents
        )
    )

    canonical_items = []

    invalid_contracts = []

    # ------------------------------------------------------------
    # NORMALIZE EACH DETECTION
    # ------------------------------------------------------------

    for detection in detections:

        if not isinstance(
            detection,
            dict,
        ):

            continue

        event_id = str(
            detection.get(
                "event_id"
            )
            or ""
        ).strip()

        matching_incidents = (
            event_incident_index.get(
                event_id,
                [],
            )
        )

        # --------------------------------------------------------
        # DETERMINISTIC PRIMARY INCIDENT
        # --------------------------------------------------------

        ordered_incidents = sorted(
            matching_incidents,
            key=_canonical_incident_sort_key,
            reverse=True,
        )

        primary_incident = (
            dict(
                ordered_incidents[0]
            )
            if ordered_incidents
            else {}
        )

        related_incident_ids = [

            str(
                incident.get(
                    "incident_id"
                )
            )

            for incident
            in ordered_incidents

            if incident.get(
                "incident_id"
            )
        ]

        if primary_incident:

            primary_incident[
                "related_incident_ids"
            ] = (
                related_incident_ids
            )

        # --------------------------------------------------------
        # CANONICAL OBJECT
        # --------------------------------------------------------

        canonical = (
            build_canonical_security_object(
                detection,
                incident=primary_incident,
            )
        )

        validation = (
            validate_canonical_security_object(
                canonical
            )
        )

        canonical[
            "contract_validation"
        ] = validation

        if not validation.get(
            "valid",
            False,
        ):

            invalid_contracts.append(
                {
                    "id":
                        canonical.get(
                            "id"
                        ),

                    "errors":
                        validation.get(
                            "errors"
                        )
                        or [],
                }
            )

        # --------------------------------------------------------
        # BACKEND VISIBILITY POLICY
        # --------------------------------------------------------

        visibility = (
            canonical.get(
                "visibility"
            )
            or {}
        )

        if (
            not include_internal
            and
            visibility.get(
                "user_visible"
            )
            is not True
        ):

            continue

        canonical_items.append(
            canonical
        )

    return {
        "schema_version":
            SECURITY_CONTRACT_VERSION,

        "status":
            "ACTIVE",

        "count":
            len(
                canonical_items
            ),

        "source_detection_count":
            len(
                detections
            ),

        "include_internal":
            bool(
                include_internal
            ),

        "contract_valid":
            len(
                invalid_contracts
            )
            ==
            0,

        "invalid_contract_count":
            len(
                invalid_contracts
            ),

        "invalid_contracts":
            invalid_contracts,

        "threats":
            canonical_items,

        "simulation_mode":
            True,

        "real_response_execution":
            False,
    }


# ================================================================
# ON-DEMAND USER SECURITY THREAT RESOLVER
# ================================================================

def _resolve_user_security_threat(
    security_id: str,
):
    """
    Resolve one user-visible canonical threat for the on-demand
    7D.4 -> 7D.9 AI pipeline.

    This function performs no AI inference and no endpoint action.
    """

    security_id = str(
        security_id
        or ""
    ).strip()

    if not security_id:
        return None

    payload = (
        _canonical_security_threats(
            limit=100,
            include_internal=False,
        )
        or {}
    )

    threats = (
        payload.get(
            "threats"
        )
        or []
    )

    for threat in threats:
        if not isinstance(
            threat,
            dict,
        ):
            continue

        if str(
            threat.get(
                "id"
            )
            or ""
        ).strip() == security_id:
            return threat

    return None


configure_user_security_analysis(
    _resolve_user_security_threat
)


# ================================================================
# CANONICAL READ-ONLY PROTECTION PREVIEW
# ================================================================

@app.get(
    "/api/v1/security/incidents/"
    "{incident_id}/protection-preview"
)
def get_canonical_protection_preview(
    incident_id: str,
):
    """
    Canonical read-only protection preview.

    Uses:
        persisted incident
            ↓
        canonical hydration
            ↓
        existing multi-agent read-only preview
            ↓
        existing Digital Twin simulation
            ↓
        canonical protection contract

    No real endpoint action is executed.
    """

    incident_id = str(
        incident_id
        or ""
    ).strip()

    if not incident_id:

        raise HTTPException(
            status_code=400,
            detail=(
                "incident_id cannot be empty."
            ),
        )

    # ------------------------------------------------------------
    # LOAD INCIDENT
    # ------------------------------------------------------------

    try:

        incident = (
            detected_incident_store
            .get_incident(
                incident_id
            )
        )

    except Exception:

        logger.exception(
            "Failed to load incident for "
            "canonical protection preview."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load security incident."
            ),
        )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Security incident was not found."
            ),
        )

    # ------------------------------------------------------------
    # USER VISIBILITY
    # ------------------------------------------------------------

    summary = (
        build_canonical_incident_summary(
            incident
        )
    )

    if (
        summary.get(
            "visibility",
            {},
        ).get(
            "user_visible"
        )
        is not True
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Security incident was not found."
            ),
        )

    # ------------------------------------------------------------
    # HYDRATE
    # ------------------------------------------------------------

    try:

        hydrated = (
            _hydrate_incident_for_analysis(
                incident
            )
        )

    except Exception:

        logger.exception(
            "Failed to hydrate incident for "
            "canonical protection preview."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to prepare incident evidence."
            ),
        )

    # ------------------------------------------------------------
    # READ-ONLY INVESTIGATION
    # ------------------------------------------------------------

    try:

        intelligence = (
            multi_agent_pipeline
            .preview_incident(
                hydrated
            )
        )

    except Exception:

        logger.exception(
            "Canonical protection investigation failed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Read-only investigation failed."
            ),
        )

    # ------------------------------------------------------------
    # EXISTING DIGITAL TWIN
    # ------------------------------------------------------------

    try:

        raw_preview = (
            canonical_protection_preview_engine
            .evaluate(
                hydrated,
                intelligence,
            )
        )

    except Exception:

        logger.exception(
            "Canonical Digital Twin preview failed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Protection preview failed."
            ),
        )

    # ------------------------------------------------------------
    # CANONICAL NORMALIZATION
    # ------------------------------------------------------------

    try:

        return (
            build_canonical_protection_preview_contract(
                hydrated,
                raw_preview,
            )
        )

    except Exception:

        logger.exception(
            "Failed to normalize canonical "
            "protection preview."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to normalize protection preview."
            ),
        )
# ================================================================
# CANONICAL USER-FACING INCIDENT LIST
# ================================================================

@app.get(
    "/api/v1/security/incidents"
)
def list_canonical_security_incidents(
    limit: int = 100,
):
    """
    User-facing canonical incident list.

    Internal regression workflow incidents are removed here,
    not by the frontend.
    """

    limit = max(
        1,
        min(
            int(limit),
            1000,
        ),
    )

    try:

        incidents = (
            detected_incident_store
            .get_incidents()
            or []
        )

        result = []

        for incident in incidents:

            if not isinstance(
                incident,
                dict,
            ):

                continue

            canonical = (
                build_canonical_incident_summary(
                    incident
                )
            )

            visibility = (
                canonical.get(
                    "visibility"
                )
                or {}
            )

            if (
                visibility.get(
                    "user_visible"
                )
                is not True
            ):

                continue

            result.append(
                canonical
            )

        # --------------------------------------------------------
        # USER-FACING SORT
        #
        # More substantial incidents first.
        # --------------------------------------------------------

        severity_rank = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
            "UNKNOWN": 0,
        }

        result.sort(
            key=lambda item: (
                int(
                    item.get(
                        "event_count"
                    )
                    or 0
                ),
                severity_rank.get(
                    str(
                        item.get(
                            "severity"
                        )
                        or ""
                    ).upper(),
                    0,
                ),
                float(
                    item.get(
                        "correlation_score"
                    )
                    or 0
                ),
            ),
            reverse=True,
        )

        result = result[
            :limit
        ]

        return {

            "schema_version":
                SECURITY_CONTRACT_VERSION,

            "count":
                len(
                    result
                ),

            "incidents":
                result,

            "simulation_mode":
                True,

            "real_response_execution":
                False,
        }

    except Exception:

        logger.exception(
            "Failed to build canonical "
            "security incident feed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to build canonical "
                "security incident feed."
            ),
        )
        
# ================================================================
# CANONICAL READ-ONLY SECURITY INVESTIGATION
# ================================================================

@app.get(
    "/api/v1/security/incidents/"
    "{incident_id}/investigation"
)
def get_canonical_security_investigation(
    incident_id: str,
):
    """
    Canonical read-only incident investigation.

    Uses the existing hydrated incident and existing multi-agent
    preview pipeline.

    Does NOT:
        - create a workflow case
        - create an approval
        - authorize a response
        - execute an endpoint action
    """

    incident_id = str(
        incident_id
        or ""
    ).strip()

    if not incident_id:

        raise HTTPException(
            status_code=400,
            detail=(
                "incident_id cannot be empty."
            ),
        )

    # ------------------------------------------------------------
    # LOAD INCIDENT
    # ------------------------------------------------------------

    try:

        incident = (
            detected_incident_store
            .get_incident(
                incident_id
            )
        )

    except Exception:

        logger.exception(
            "Failed to load incident for "
            "canonical investigation."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load the "
                "security incident."
            ),
        )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Security incident "
                "was not found."
            ),
        )

    # ------------------------------------------------------------
    # DO NOT EXPOSE INTERNAL REGRESSION INCIDENTS
    # ------------------------------------------------------------

    summary = (
        build_canonical_incident_summary(
            incident
        )
    )

    if (
        summary.get(
            "visibility",
            {},
        ).get(
            "user_visible"
        )
        is not True
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Security incident "
                "was not found."
            ),
        )

    # ------------------------------------------------------------
    # HYDRATE USING THE SAME CONTRACT AS EXISTING AI INVESTIGATION
    # ------------------------------------------------------------

    try:

        hydrated = (
            _hydrate_incident_for_analysis(
                incident
            )
        )

    except Exception:

        logger.exception(
            "Failed to hydrate incident for "
            "canonical investigation."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to prepare incident "
                "evidence for investigation."
            ),
        )

    # ------------------------------------------------------------
    # EXISTING READ-ONLY MULTI-AGENT PIPELINE
    # ------------------------------------------------------------

    try:

        intelligence = (
            multi_agent_pipeline
            .preview_incident(
                hydrated
            )
        )

    except Exception:

        logger.exception(
            "Canonical read-only "
            "investigation failed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Read-only security "
                "investigation failed."
            ),
        )

    # ------------------------------------------------------------
    # CANONICAL NORMALIZATION
    # ------------------------------------------------------------

    try:

        return (
            build_canonical_investigation_contract(
                hydrated,
                intelligence,
            )
        )

    except Exception:

        logger.exception(
            "Failed to normalize canonical "
            "investigation contract."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to normalize security "
                "investigation results."
            ),
        )
# ================================================================
# CANONICAL USER-FACING THREAT LIST
# ================================================================

@app.get(
    "/api/v1/security/threats"
)
def list_canonical_security_threats(
    limit: int = 100,
    include_internal: bool = False,
):
    """
    Canonical user-facing threat feed.

    This endpoint is the migration target for Threats.jsx.

    By default:
        - internal regression fixtures are hidden
        - raw SOC workflow records are hidden
        - synthetic product threats remain visible
    """

    try:

        return (
            _canonical_security_threats(
                limit=limit,
                include_internal=include_internal,
            )
        )

    except HTTPException:

        raise

    except Exception:

        logger.exception(
            "Failed to build canonical "
            "security threat feed."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to build canonical "
                "security threat feed."
            ),
        )
        
# ================================================================
# CANONICAL USER-FACING THREAT DETAIL
# ================================================================

@app.get(
    "/api/v1/security/threats/{security_id}"
)
def get_canonical_security_threat(
    security_id: str,
):
    """
    Retrieve one canonical threat.

    Expected canonical id examples:

        detection-2
        detection-7
    """

    security_id = str(
        security_id
        or ""
    ).strip()

    if not security_id:

        raise HTTPException(
            status_code=400,
            detail=(
                "security_id cannot be empty."
            ),
        )

    try:

        payload = (
            _canonical_security_threats(
                limit=100,
                include_internal=True,
            )
        )

        for threat in (
            payload.get(
                "threats"
            )
            or []
        ):

            if str(
                threat.get(
                    "id"
                )
                or ""
            ) == security_id:

                visibility = (
                    threat.get(
                        "visibility"
                    )
                    or {}
                )

                # Normal product endpoint must not expose
                # internal regression objects.
                if visibility.get(
                    "user_visible"
                ) is not True:

                    raise HTTPException(
                        status_code=404,
                        detail=(
                            "Security threat "
                            "was not found."
                        ),
                    )

                return threat

        raise HTTPException(
            status_code=404,
            detail=(
                "Security threat "
                "was not found."
            ),
        )

    except HTTPException:

        raise

    except Exception:

        logger.exception(
            "Failed to retrieve canonical "
            "security threat."
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve canonical "
                "security threat."
            ),
        )
# ================================================================

# ENDPOINT OVERVIEW

# ================================================================

@app.get("/api/v1/endpoint/overview")

def endpoint_overview(recent_limit: int = 25):

    recent_limit = max(

        1,

        min(recent_limit, 100),

    )

    try:

        endpoint_data = (

            get_endpoint_database_summary(

                recent_limit=recent_limit

            )

            or {}

        )

        detected_incidents = (

            detected_incident_store.get_incidents()

            or []

        )

        if not isinstance(detected_incidents, list):

            detected_incidents = []

        promoted_incident_count = 0

        for incident in detected_incidents:

            if not isinstance(incident, dict):

                continue

            incident_id = incident.get("incident_id")

            if not incident_id:

                continue

            try:

                soc_case = workflow.recover_case(

                    incident_id

                )

            except Exception:

                soc_case = None

            if soc_case is not None:

                promoted_incident_count += 1

        incident_count = len(detected_incidents)

        awaiting_investigation_count = max(

            0,

            incident_count - promoted_incident_count,

        )

        collector_states = {

            "process": "OFFLINE",

            "file": "OFFLINE",

            "network": "OFFLINE",

            "registry": "OFFLINE",


            "auth": "OFFLINE",

        }

        if sentinel_agent is not None:

            for collector_name, thread in (

                sentinel_agent.collector_threads.items()

            ):

                collector_states[collector_name] = (

                    "ACTIVE"

                    if thread.is_alive()

                    else "OFFLINE"

                )

        return {

            "status": "HEALTHY",

            "timestamp": now_iso(),

            "data_source": "ENDPOINT_SQLITE_DATABASE",

            "simulation_mode": True,

            "real_response_execution": False,

            "collector_runtime_tracking": True,

            "live_collection_started_by_api": bool(

                sentinel_agent is not None

                and sentinel_agent.running

            ),

            "collectors": collector_states,

            "note": (

                "Collectors are managed continuously "

                "by the SENTINEL-X Endpoint Agent."

            ),

            "event_count": int(

                endpoint_data.get("event_count", 0) or 0

            ),

            "detection_count": int(

                endpoint_data.get("detection_count", 0) or 0

            ),

            "incident_count": incident_count,

            "promoted_incident_count":

                promoted_incident_count,

            "awaiting_investigation_count":

                awaiting_investigation_count,

            "event_severity_counts":

                endpoint_data.get(

                    "event_severity_counts", {}

                ) or {},

            "detection_severity_counts":

                endpoint_data.get(

                    "detection_severity_counts", {}

                ) or {},

            "detection_engine_counts":

                endpoint_data.get(

                    "detection_engine_counts", {}

                ) or {},

            "detection_type_counts":

                endpoint_data.get(

                    "detection_type_counts", {}

                ) or {},

            "event_category_counts":

                endpoint_data.get(

                    "event_category_counts", {}

                ) or {},

            "events":

                endpoint_data.get("events", []) or [],

            "detections":

                endpoint_data.get("detections", []) or [],

            "recent_limit": recent_limit,

        }

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=f"Failed to load endpoint overview: {error}",

        )

# ================================================================

# DASHBOARD SUMMARY

# ================================================================

@app.get("/api/v1/dashboard/summary")

def dashboard_summary():

    try:

        cases = (

            workflow.list_cases(limit=1000)

            or []

        )

        tickets = (

            ticket_store.list_tickets(limit=1000)

            or []

        )

        actions = (

            workflow.action_store.list_actions(limit=1000)

            or []

        )

        endpoint_data = (

            get_endpoint_database_summary(recent_limit=1)

            or {}

        )

        detected_incidents = (

            detected_incident_store.get_incidents()

            or []

        )

        if not isinstance(detected_incidents, list):

            detected_incidents = []

        def get_value(item, key, default=None):

            if isinstance(item, dict):

                return item.get(key, default)

            return getattr(item, key, default)

        soc_case_ids = set()

        for case in cases:

            case_incident_id = get_value(

                case,

                "incident_id",

            )

            if case_incident_id:

                soc_case_ids.add(

                    str(case_incident_id)

                )

        detected_incident_count = len(

            detected_incidents

        )

        promoted_incident_count = 0

        for incident in detected_incidents:

            detected_id = get_value(

                incident,

                "incident_id",

            )

            if (

                detected_id

                and str(detected_id) in soc_case_ids

            ):

                promoted_incident_count += 1

        awaiting_investigation_count = max(

            0,

            detected_incident_count

            - promoted_incident_count,

        )

        incident_severity_counts = {

            "CRITICAL": 0,

            "HIGH": 0,

            "MEDIUM": 0,

            "LOW": 0,

            "INFO": 0,

            "UNKNOWN": 0,

        }

        for incident in detected_incidents:

            severity = str(

                get_value(

                    incident,

                    "severity",

                    "UNKNOWN",

                )

                or "UNKNOWN"

            ).upper()

            if severity not in incident_severity_counts:

                severity = "UNKNOWN"

            incident_severity_counts[severity] += 1

        priority_counts = {

            "P1": 0,

            "P2": 0,

            "P3": 0,

            "P4": 0,

        }

        for ticket in tickets:

            priority = str(

                get_value(

                    ticket,

                    "priority",

                    "P4",

                )

                or "P4"

            ).upper()

            if priority not in priority_counts:

                priority = "P4"

            priority_counts[priority] += 1

        pending_approvals = 0

        approved_tickets = 0

        rejected_tickets = 0

        open_tickets = 0

        for ticket in tickets:

            approval_status = str(

                get_value(

                    ticket,

                    "approval_status",

                    "",

                )

                or ""

            ).upper()

            ticket_status = str(

                get_value(

                    ticket,

                    "status",

                    "OPEN",

                )

                or "OPEN"

            ).upper()

            if approval_status == "PENDING":

                pending_approvals += 1

            elif approval_status == "APPROVED":

                approved_tickets += 1

            elif approval_status == "REJECTED":

                rejected_tickets += 1

            if ticket_status not in {

                "CLOSED",

                "RESOLVED",

                "REJECTED",

            }:

                open_tickets += 1

        pending_cases = 0

        critical_cases = 0

        high_cases = 0

        medium_cases = 0

        low_cases = 0

        info_cases = 0

        mitigation_status_counts = {

            "VERIFIED": 0,

            "PARTIAL": 0,

            "FAILED": 0,

            "NOT_VERIFIED": 0,

            "UNKNOWN": 0,

        }

        for case in cases:

            case_status = str(

                get_value(

                    case,

                    "case_status",

                    get_value(case, "status", ""),

                )

                or ""

            ).upper()

            if (

                case_status

                == "AWAITING_ANALYST_REVIEW"

            ):

                pending_cases += 1

            risk_level = str(

                get_value(

                    case,

                    "risk_level",

                    "INFO",

                )

                or "INFO"

            ).upper()

            if risk_level == "CRITICAL":

                critical_cases += 1

            elif risk_level == "HIGH":

                high_cases += 1

            elif risk_level == "MEDIUM":

                medium_cases += 1

            elif risk_level == "LOW":

                low_cases += 1

            else:

                info_cases += 1

            case_incident_id = get_value(

                case,

                "incident_id",

            )

            mitigation_verification = {}

            if case_incident_id:

                try:

                    mitigation_verification = (

                        workflow.get_mitigation_verification(

                            case_incident_id

                        )

                        or {}

                    )

                except Exception:

                    mitigation_verification = {}

            mitigation_status = str(

                mitigation_verification.get(

                    "status",

                    "NOT_VERIFIED",

                )

                or "NOT_VERIFIED"

            ).upper()

            if mitigation_status in {

                "VERIFIED",

                "SIMULATION_VERIFIED",

                "MITIGATION_VERIFIED",

            }:

                mitigation_key = "VERIFIED"

            elif mitigation_status in {

                "PARTIAL",

                "SIMULATION_PARTIAL",

                "PARTIALLY_VERIFIED",

                "PARTIAL_SUCCESS",

            }:

                mitigation_key = "PARTIAL"

            elif mitigation_status in {

                "FAILED",

                "SIMULATION_NO_IMPROVEMENT",

                "MITIGATION_FAILED",

            }:

                mitigation_key = "FAILED"

            elif mitigation_status in {

                "NOT_VERIFIED",

                "PENDING",

                "NOT_RUN",

            }:

                mitigation_key = "NOT_VERIFIED"

            else:

                mitigation_key = "UNKNOWN"

            mitigation_status_counts[

                mitigation_key

            ] += 1

        ready_actions = 0

        pending_actions = 0

        successful_actions = 0

        failed_actions = 0

        for action in actions:

            execution_status = str(

                get_value(

                    action,

                    "execution_status",

                    "",

                )

                or ""

            ).upper()

            approval_status = str(

                get_value(

                    action,

                    "approval_status",

                    "",

                )

                or ""

            ).upper()

            if execution_status == "READY":

                ready_actions += 1

            elif execution_status == "SUCCESS":

                successful_actions += 1

            elif execution_status == "FAILED":

                failed_actions += 1

            if approval_status == "PENDING":

                pending_actions += 1

        event_count = int(

            endpoint_data.get("event_count", 0) or 0

        )

        detection_count = int(

            endpoint_data.get("detection_count", 0) or 0

        )

        event_category_counts = (

            endpoint_data.get(

                "event_category_counts", {}

            ) or {}

        )

        event_severity_counts = (

            endpoint_data.get(

                "event_severity_counts", {}

            ) or {}

        )

        detection_severity_counts = (

            endpoint_data.get(

                "detection_severity_counts", {}

            ) or {}

        )

        detection_engine_counts = (

            endpoint_data.get(

                "detection_engine_counts", {}

            ) or {}

        )

        detection_type_counts = (

            endpoint_data.get(

                "detection_type_counts", {}

            ) or {}

        )

        return {

            "timestamp": now_iso(),

            "data_source": "ENDPOINT_SQLITE_DATABASE",

            "event_count": event_count,

            "detection_count": detection_count,

            "event_category_counts":

                event_category_counts,

            "event_severity_counts":

                event_severity_counts,

            "detection_severity_counts":

                detection_severity_counts,

            "detection_engine_counts":

                detection_engine_counts,

            "detection_type_counts":

                detection_type_counts,

            "detected_incidents":

                detected_incident_count,

            "total_detected_incidents":

                detected_incident_count,

            "awaiting_investigation":

                awaiting_investigation_count,

            "awaiting_investigation_count":

                awaiting_investigation_count,

            "promoted_to_soc":

                promoted_incident_count,

            "promoted_incident_count":

                promoted_incident_count,

            "incident_severity_counts":

                incident_severity_counts,

            "persistent_soc_cases": len(cases),

            "pending_soc_cases": pending_cases,

            "critical_cases": critical_cases,

            "high_cases": high_cases,

            "medium_cases": medium_cases,

            "low_cases": low_cases,

            "info_cases": info_cases,

            "total_tickets": len(tickets),

            "open_tickets": open_tickets,

            "pending_approvals": pending_approvals,

            "approved_tickets": approved_tickets,

            "rejected_tickets": rejected_tickets,

            "priority_counts": priority_counts,

            "total_response_actions": len(actions),

            "pending_response_actions":

                pending_actions,

            "ready_response_actions":

                ready_actions,

            "successful_response_actions":

                successful_actions,

            "failed_response_actions":

                failed_actions,

            "mitigation_status_counts":

                mitigation_status_counts,

            "verified_mitigations":

                mitigation_status_counts["VERIFIED"],

            "partial_mitigations":

                mitigation_status_counts["PARTIAL"],

            "failed_mitigations":

                mitigation_status_counts["FAILED"],

            "not_verified_mitigations":

                mitigation_status_counts["NOT_VERIFIED"],

            "simulation_mode": True,

            "persistent_recovery": True,

            "real_response_execution": False,

            "collector_runtime_tracking": True,

            "live_collection_started_by_api": bool(

                sentinel_agent is not None

                and sentinel_agent.running

            ),

        }

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=f"Failed to load dashboard summary: {error}",

        )

# ================================================================

# CREATE SOC CASE

# ================================================================

@app.post("/api/v1/cases")

def create_case(request: CreateCaseRequest):

    # Fail closed: public callers must not submit arbitrary AI
    # intelligence and bypass validated incident investigation.
    # Use POST /api/v1/detected-incidents/{incident_id}/investigate.
    # This path has no authentication/authorization boundary.
    raise HTTPException(
        status_code=403,
        detail=(
            "Direct SOC case creation is disabled. Investigate a "
            "stored incident through the validated investigation route."
        ),
    )

    incident_id = request.incident_id.strip()

    if not incident_id:

        raise HTTPException(

            status_code=400,

            detail="incident_id cannot be empty.",

        )

    existing = workflow.recover_case(

        incident_id

    )

    if existing is not None:

        raise HTTPException(

            status_code=409,

            detail=(

                f"SOC case already exists for "

                f"incident {incident_id}."

            ),

        )

    try:

        case = workflow.create_case(

            incident_id=incident_id,

            intelligence=request.intelligence,

        )

        return {

            "success": True,

            "incident_id": incident_id,

            "status": case.get("status"),

            "ticket": serialize_value(

                case.get("ticket_data")

            ),

            "response_action_count":

                case.get("response_action_count", 0),

            "digital_twin_decision":

                serialize_value(case.get("decision")),

            "explanation":

                serialize_value(case.get("explanation")),

            "response_actions":

                serialize_value(case.get("response_actions")),

            "evidence":

                serialize_value(case.get("evidence", {})),

            "timeline":

                serialize_value(case.get("timeline", [])),

            "persistence":

                serialize_value(case.get("persistence")),

            "simulation_mode": True,

            "persistent_recovery": True,

            "real_response_executed": False,

        }

    except HTTPException:

        raise

    except ValueError as error:

        raise HTTPException(

            status_code=409,

            detail=str(error),

        )

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=f"Failed to create SOC case: {error}",

        )

# ================================================================

# LIST SOC CASES

# ================================================================

@app.get("/api/v1/cases")

def list_cases(limit: int = 100):

    limit = max(1, min(limit, 1000))

    cases = workflow.list_cases(

        limit=limit

    )

    return {

        "count": len(cases),

        "persistent": True,

        "cases": serialize_value(cases),

    }

# ================================================================

# LIST DETECTED INCIDENTS

# ================================================================

@app.get("/api/v1/detected-incidents")

def list_detected_incidents(limit: int = 100):

    limit = max(1, min(limit, 1000))

    try:

        incidents = (

            detected_incident_store.get_incidents()

            or []

        )

        incidents = incidents[:limit]

        enriched_incidents = [

            enrich_detected_incident(incident)

            for incident in incidents

        ]

        return {

            "count": len(enriched_incidents),

            "source": "CORRELATION_INCIDENT_STORE",

            "persistent": True,

            "incidents": serialize_value(

                enriched_incidents

            ),

            "simulation_mode": True,

            "real_response_executed": False,

        }

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Failed to retrieve detected "

                f"incidents: {error}"

            ),

        )

# ================================================================

# GET DETECTED INCIDENT

# ================================================================

@app.get("/api/v1/detected-incidents/{incident_id}")

def get_detected_incident(incident_id: str):

    try:

        incident = (

            detected_incident_store.get_incident(

                incident_id

            )

        )

        if incident is None:

            raise HTTPException(

                status_code=404,

                detail=(

                    f"Detected incident {incident_id} "

                    "was not found."

                ),

            )

        incident = _hydrate_incident_for_analysis(incident)

        return enrich_detected_incident(

            incident

        )

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Failed to retrieve detected "

                f"incident: {error}"

            ),

        )

# ================================================================
# READ-ONLY ANALYTICAL PREVIEW
# ================================================================

@app.get("/api/v1/detected-incidents/{incident_id}/analysis-preview")
def preview_detected_incident(incident_id: str):
    """Compute provisional analysis. Never persist a SOC workflow."""
    incident_id = incident_id.strip()
    if not incident_id:
        raise HTTPException(status_code=400, detail="incident_id cannot be empty.")

    try:
        incident = detected_incident_store.get_incident(incident_id)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load detected incident: {error}",
        )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"Detected incident {incident_id} was not found.",
        )

    incident = _hydrate_incident_for_analysis(incident)

    try:
        intelligence = multi_agent_pipeline.preview_incident(incident)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Read-only analysis failed: {error}",
        )

    return {
        "success": True,
        "preview_only": True,
        "read_only": True,
        "already_in_soc": False,
        "soc_case_created": False,
        "incident_id": incident_id,
        "status": "PREVIEW_ONLY",
        "multi_agent": {
            "status": intelligence.get("status", "UNKNOWN"),
            "security_state": intelligence.get("security_state"),
            "risk_score": intelligence.get("risk_score", 0),
            "risk_level": intelligence.get("risk_level", "INFO"),
            "final_decision": intelligence.get("final_decision"),
            "execution_enabled": False,
        },
        "intelligence": serialize_value(intelligence),
        "response_action_count": 0,
        "simulation_mode": True,
        "real_response_executed": False,
    }

# ================================================================

# INVESTIGATE DETECTED INCIDENT

# ================================================================

@app.post(

    "/api/v1/detected-incidents/{incident_id}/investigate"

)

def investigate_detected_incident(

    incident_id: str

):

    incident_id = incident_id.strip()

    if not incident_id:

        raise HTTPException(

            status_code=400,

            detail="incident_id cannot be empty.",

        )

    try:

        incident = (

            detected_incident_store.get_incident(

                incident_id

            )

        )

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Failed to load detected "

                f"incident: {error}"

            ),

        )

    if incident is None:

        raise HTTPException(

            status_code=404,

            detail=(

                f"Detected incident {incident_id} "

                "was not found."

            ),

        )

    incident = _hydrate_incident_for_analysis(incident)

    existing = workflow.recover_case(

        incident_id

    )

    if existing is not None:

        return {

            "success": True,

            "already_in_soc": True,

            "incident_id": incident_id,

            "status": existing.get("status"),

            "ticket": serialize_value(

                existing.get("ticket_data", {})

            ),

            "response_action_count":

                existing.get("response_action_count", 0),

            "response_actions": serialize_value(

                existing.get("response_actions", [])

            ),

            "digital_twin_decision": serialize_value(

                existing.get("decision", {})

            ),

            "simulation_mode": True,

            "real_response_executed": False,

        }

    try:

        intelligence = (

            multi_agent_pipeline.process_incident(

                incident

            )

        )

        if not isinstance(intelligence, dict):

            raise ValueError(

                "Multi-agent pipeline returned "

                "an invalid intelligence result."

            )

        intelligence["source_incident"] = incident

        coordinated_analysis = (

            intelligence.get(

                "coordinated_analysis"

            )

        )

        if not isinstance(

            coordinated_analysis,

            dict,

        ):

            raise ValueError(

                "Multi-agent pipeline did not "

                "produce coordinated_analysis."

            )

        pipeline_status = str(

            intelligence.get("status", "UNKNOWN")

        ).upper()

        if pipeline_status != "COMPLETED":
            raise ValueError(
            "Multi-agent investigation cannot create an SOC case. "
            f"Pipeline status: {pipeline_status}. "
            "Review agent failures or insufficient evidence first."
        )

        case = workflow.create_case(

            incident_id=incident_id,

            intelligence=intelligence,

        )

        return {

            "success": True,

            "already_in_soc": False,

            "incident_id": incident_id,

            "detected_incident":

                serialize_value(incident),

            "multi_agent": {

                "status":

                    intelligence.get("status"),

                "security_state":

                    intelligence.get("security_state"),

                "risk_score":

                    intelligence.get("risk_score", 0),

                "risk_level":

                    intelligence.get("risk_level", "INFO"),

                "final_decision":

                    intelligence.get("final_decision", "MONITOR"),

                "autonomy_level":

                    intelligence.get("autonomy_level"),

                "autonomy_mode":

                    intelligence.get("autonomy_mode"),

                "execution_enabled":

                    intelligence.get(

                        "execution_enabled",

                        False,

                    ),

            },

            "intelligence":

                serialize_value(intelligence),

            "status":

                case.get("status"),

            "ticket":

                serialize_value(

                    case.get("ticket_data", {})

                ),

            "response_action_count":

                case.get("response_action_count", 0),

            "response_actions":

                serialize_value(

                    case.get("response_actions", [])

                ),

            "digital_twin_decision":

                serialize_value(

                    case.get("decision", {})

                ),

            "explanation":

                serialize_value(

                    case.get("explanation", {})

                ),

            "persistence":

                serialize_value(

                    case.get("persistence", {})

                ),

            "simulation_mode": True,

            "real_response_executed": False,

        }

    except HTTPException:

        raise

    except ValueError as error:

        raise HTTPException(

            status_code=422,

            detail=str(error),

        )

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Failed to investigate detected "

                f"incident: {error}"

            ),

        )

# ================================================================

# GET SOC CASE

# ================================================================

@app.get("/api/v1/cases/{incident_id}")

def get_case(incident_id: str):

    case = require_case(

        incident_id

    )

    return {

        "incident_id": incident_id,

        "status": case.get("status"),

        "ticket": serialize_value(

            case.get("ticket_data")

        ),

        "decision": serialize_value(

            case.get("decision")

        ),

        "explanation": serialize_value(

            case.get("explanation")

        ),

        "response_actions": serialize_value(

            case.get("response_actions")

        ),

        "response_action_count":

            case.get("response_action_count", 0),

        "evidence": serialize_value(

            case.get("evidence", {})

        ),

        "timeline": serialize_value(

            case.get("timeline", [])

        ),

        "recovered_from_database":

            case.get("recovered_from_database", False),

        "simulation_mode": True,

        "real_response_executed": False,

    }

# ================================================================

# GET MITIGATION VERIFICATION

# ================================================================

@app.get(

    "/api/v1/cases/{incident_id}/mitigation-verification"

)

def get_mitigation_verification(

    incident_id: str

):

    require_case(incident_id)

    verification = (

        workflow.get_mitigation_verification(

            incident_id

        )

    )

    if not verification:

        return {

            "incident_id": incident_id,

            "status": "NOT_VERIFIED",

            "verified": False,

            "verification": {},

            "persistent": True,

            "simulation_mode": True,

            "real_response_executed": False,

        }

    return {

        "incident_id": incident_id,

        "status": verification.get("status"),

        "verified": True,

        "verification":

            serialize_value(verification),

        "persistent": True,

        "simulation_mode": True,

        "real_response_executed": False,

    }

# ================================================================

# RUN SIMULATED MITIGATION VERIFICATION

# ================================================================

@app.post(

    "/api/v1/cases/{incident_id}/mitigation-verification"

)

def run_mitigation_verification(

    incident_id: str,

    request: MitigationVerificationRequest,

):

    require_case(incident_id)

    try:

        if (

            request.response_result.get(

                "simulation_mode",

                True,

            )

            is not True

        ):

            raise ValueError(

                "Only simulation-mode response results "

                "can be verified through this API."

            )

        result = (

            workflow.verify_simulated_mitigation(

                incident_id=incident_id,

                before_state=request.before_state,

                simulated_after_state=

                    request.simulated_after_state,

                response_result=request.response_result,

            )

        )

        return {

            "success": result.get("success", False),

            "incident_id": incident_id,

            "status": result.get("status"),

            "verification": serialize_value(

                result.get("verification", {})

            ),

            "persisted":

                result.get("persisted", False),

            "simulation_mode": True,

            "real_response_executed": False,

        }

    except TypeError as error:

        raise HTTPException(

            status_code=400,

            detail=str(error),

        )

    except ValueError as error:

        raise HTTPException(

            status_code=409,

            detail=str(error),

        )

    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Mitigation verification failed: "

                f"{error}"

            ),

        )

# ================================================================

# DIGITAL TWIN

# ================================================================

@app.get(

    "/api/v1/cases/{incident_id}/digital-twin"

)

def get_digital_twin(incident_id: str):

    case = require_case(incident_id)

    return {

        "incident_id": incident_id,

        "decision": serialize_value(

            case.get("decision")

        ),

        "explanation": serialize_value(

            case.get("explanation")

        ),

        "recovered_from_database":

            case.get(

                "recovered_from_database",

                False,

            ),

        "simulation_mode": True,

        "real_endpoint_modified": False,

    }

# ================================================================

# RESPONSE ACTIONS

# ================================================================

@app.get(

    "/api/v1/cases/{incident_id}/responses"

)

def get_response_actions(incident_id: str):

    require_case(incident_id)

    actions = workflow.get_response_actions(

        incident_id

    )

    return {

        "incident_id": incident_id,

        "count": len(actions),

        "actions": serialize_value(actions),

        "persistent": True,

        "simulation_mode": True,

        "real_response_executed": False,

    }

# ================================================================

# INCIDENT EVIDENCE

# ================================================================

@app.get(

    "/api/v1/cases/{incident_id}/evidence"

)

def get_case_evidence(incident_id: str):

    require_case(incident_id)

    evidence = workflow.get_evidence(

        incident_id

    )

    return

# ================================================================
# INCIDENT TIMELINE
# ================================================================

@app.get(
    "/api/v1/cases/{incident_id}/timeline"
)
def get_case_timeline(
    incident_id: str,
):

    require_case(
        incident_id
    )

    timeline = (
        workflow.get_timeline(
            incident_id
        )
    )

    return {
        "incident_id":
            incident_id,

        "count":
            len(
                timeline
            ),

        "persistent":
            True,

        "timeline":
            serialize_value(
                timeline
            ),
    }


# ================================================================
# APPROVE SOC CASE
# ================================================================

@app.post(
    "/api/v1/cases/{incident_id}/approve"
)
def approve_case(
    incident_id: str,
    request: AnalystDecisionRequest,
):

    require_case(
        incident_id
    )

    try:

        result = (
            workflow.approve_case(
                incident_id=
                    incident_id,

                analyst=
                    request.analyst,

                comment=
                    request.comment,
            )
        )

        return serialize_value(
            result
        )

    except ValueError as error:

        raise HTTPException(
            status_code=409,
            detail=str(
                error
            ),
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Approval workflow failed: "
                f"{error}"
            ),
        )


# ================================================================
# REJECT SOC CASE
# ================================================================

@app.post(
    "/api/v1/cases/{incident_id}/reject"
)
def reject_case(
    incident_id: str,
    request: AnalystRejectionRequest,
):

    require_case(
        incident_id
    )

    try:

        result = (
            workflow.reject_case(
                incident_id=
                    incident_id,

                analyst=
                    request.analyst,

                reason=
                    request.reason,
            )
        )

        return serialize_value(
            result
        )

    except ValueError as error:

        raise HTTPException(
            status_code=409,
            detail=str(
                error
            ),
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Rejection workflow failed: "
                f"{error}"
            ),
        )


# ================================================================
# LIST SOC TICKETS
# ================================================================

@app.get(
    "/api/v1/tickets"
)
def list_tickets(
    limit: int = 100,
):

    limit = max(
        1,
        min(
            limit,
            1000,
        ),
    )

    tickets = (
        ticket_store.list_tickets(
            limit=limit
        )
    )

    return {
        "count":
            len(
                tickets
            ),

        "tickets":
            serialize_value(
                tickets
            ),
    }


# ================================================================
# GET SOC TICKET
# ================================================================

@app.get(
    "/api/v1/tickets/{ticket_id}"
)
def get_ticket(
    ticket_id: str,
):

    ticket = (
        ticket_store.get_ticket(
            ticket_id
        )
    )

    if ticket is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"Ticket {ticket_id} "
                "not found."
            ),
        )

    return serialize_value(
        ticket
    )


# ================================================================
# GET TICKETS FOR INCIDENT
# ================================================================

@app.get(
    "/api/v1/incidents/{incident_id}/tickets"
)
def get_incident_tickets(
    incident_id: str,
):

    tickets = (
        ticket_store.get_by_incident(
            incident_id
        )
    )

    return {
        "incident_id":
            incident_id,

        "count":
            len(
                tickets
            ),

        "tickets":
            serialize_value(
                tickets
            ),
    }


# ================================================================
# COMPLETE INCIDENT DETAIL
# ================================================================

@app.get(
    "/api/v1/incidents/{incident_id}/full"
)
def get_full_incident(
    incident_id: str,
):

    result = (
        incident_view_service
        .get_full_incident(
            incident_id
        )
    )

    if result is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"Incident {incident_id} "
                "was not found."
            ),
        )

    return serialize_value(
        result
    )