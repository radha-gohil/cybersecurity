from typing import Any

from datetime import datetime, timezone

import threading

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

    logger.info("Starting SENTINEL-X backend runtime...")

    with sentinel_agent_lock:

        existing_thread_alive = (

            sentinel_agent_thread is not None

            and sentinel_agent_thread.is_alive()

        )

        if not existing_thread_alive:

            sentinel_agent = SentinelAgent()

            sentinel_agent_thread = threading.Thread(

                target=run_sentinel_agent,

                name="SentinelXEndpointAgent",

                daemon=True,

            )

            sentinel_agent_thread.start()

            logger.info(

                "SENTINEL-X Endpoint Agent background thread started."

            )

        else:

            logger.warning(

                "SENTINEL-X Endpoint Agent is already running."

            )

    app.state.sentinel_agent = sentinel_agent

    app.state.telemetry_manager = shared_telemetry_manager

    logger.info("SENTINEL-X FastAPI runtime started.")

    logger.info("=" * 78)

    try:

        yield

    finally:

        logger.info("=" * 78)

        logger.info("Stopping SENTINEL-X backend runtime...")

        with sentinel_agent_lock:

            if sentinel_agent is not None:

                try:

                    sentinel_agent.stop()

                except Exception as error:

                    logger.exception(

                        "Unable to stop SentinelAgent cleanly | %s",

                        error,

                    )

            if (

                sentinel_agent_thread is not None

                and sentinel_agent_thread.is_alive()

            ):

                sentinel_agent_thread.join(timeout=10)

        logger.info("SENTINEL-X backend runtime stopped.")

        logger.info("=" * 78)

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

app.include_router(build_digital_twin_visual_router(
    detected_incident_store, multi_agent_pipeline
))

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

            and healthy_count == 4

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

            "expected_collector_count": 4,

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

    Resolve the existing Sentinel-X endpoint SQLite database.

    api/main.py

        -> project root

        -> data/database/sentinel_endpoint.db

    """

    return (

        Path(__file__)

        .resolve()

        .parents[1]

        / "data"

        / "database"

        / "sentinel_endpoint.db"

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

def _build_detection_evidence(

    event_record,

):

    """

    Convert a persisted endpoint event into a small,

    frontend-safe evidence object.

    This does NOT assign an attack family.

    """

    if not event_record:

        return {

            "event_found": False,

        }

    process_data = _safe_json_dict(

        event_record.get(

            "process_data"

        )

    )

    file_data = _safe_json_dict(

        event_record.get(

            "file_data"

        )

    )

    network_data = _safe_json_dict(

        event_record.get(

            "network_data"

        )

    )

    registry_data = _safe_json_dict(

        event_record.get(

            "registry_data"

        )

    )

    metadata = _safe_json_dict(

        event_record.get(

            "metadata"

        )

    )

    process_name = (

        process_data.get("name")

        or process_data.get(

            "process_name"

        )

    )

    parent_process_name = (

        process_data.get(

            "parent_name"

        )

        or process_data.get(

            "parent_process_name"

        )

    )

    # ------------------------------------------------------------

    # PROCESS / MODEL EVIDENCE

    # ------------------------------------------------------------

    process_evidence = {

        "pid":

            process_data.get("pid"),

        "ppid":

            process_data.get("ppid"),

        "process_name":

            process_name,

        "parent_process_name":

            parent_process_name,

        "create_time":

            process_data.get(

                "create_time"

            ),

        "cpu_percent":

            process_data.get(

                "cpu_percent"

            ),

        "memory_percent":

            process_data.get(

                "memory_percent"

            ),

        "rss_mb":

            process_data.get(

                "rss_mb"

            ),

        "num_threads":

            process_data.get(

                "num_threads"

            ),

        "num_handles":

            process_data.get(

                "num_handles"

            ),

        "fusion_version":

            process_data.get(

                "fusion_version"

            ),

        "fusion_score":

            process_data.get(

                "fusion_score"

            ),

        "fusion_severity":

            process_data.get(

                "fusion_severity"

            ),

        "fusion_confidence":

            process_data.get(

                "fusion_confidence"

            ),

        "fusion_reasons":

            process_data.get(

                "fusion_reasons"

            ),

        "ai_consensus_score":

            process_data.get(

                "ai_consensus_score"

            ),

        "ai_consensus":

            process_data.get(

                "ai_consensus"

            ),

        "isolation_forest":

            process_data.get(

                "isolation_forest"

            ),

        "autoencoder":

            process_data.get(

                "autoencoder"

            ),

        "ai_behavior_context":

            process_data.get(

                "ai_behavior_context"

            ),

    }

    # ------------------------------------------------------------

    # FUSION / METADATA SCORES

    # ------------------------------------------------------------

    model_scores = {

        "rule_score":

            metadata.get(

                "rule_score"

            ),

        "statistical_score":

            metadata.get(

                "statistical_score"

            ),

        "isolation_forest_score":

            metadata.get(

                "isolation_forest_score"

            ),

        "autoencoder_score":

            metadata.get(

                "autoencoder_score"

            ),

        "ai_consensus_score":

            metadata.get(

                "ai_consensus_score"

            ),

        "ai_agreement":

            metadata.get(

                "ai_agreement"

            ),

        "ai_disagreement":

            metadata.get(

                "ai_disagreement"

            ),

        "fusion_score":

            metadata.get(

                "fusion_score"

            ),

        "evidence_confidence":

            metadata.get(

                "evidence_confidence"

            ),

        "critical_allowed":

            metadata.get(

                "critical_allowed"

            ),

        "feature_record_id":

            metadata.get(

                "feature_record_id"

            ),

        "event_category":

            metadata.get(

                "event_category"

            ),

    }

    # ------------------------------------------------------------

    # OTHER TELEMETRY

    #

    # These fields remain empty for a process-only fusion event

    # unless the persisted event actually contains that modality.

    # ------------------------------------------------------------

    return {

        "event_found": True,

        "event": {

            "timestamp":

                event_record.get(

                    "timestamp"

                ),

            "device_id":

                event_record.get(

                    "device_id"

                ),

            "event_type":

                event_record.get(

                    "event_type"

                ),

            "severity":

                event_record.get(

                    "severity"

                ),

            "source":

                event_record.get(

                    "source"

                ),

        },

        "process":

            process_evidence,

        "model_scores":

            model_scores,

        "file":

            file_data,

        "network":

            network_data,

        "registry":

            registry_data,

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
                    display_title = f"{category} — {process_name}"
                else:
                    display_title = category

            elif process_name and event_type == "process_fusion_detection":

                display_title = f"Behavioral AI alert — {process_name}"

            elif process_name:

                display_title = f"Process alert — {process_name}"

            else:

                display_title = str(
                    threat_type or "Security detection"
                ).replace("_", " ")

            detections.append({
                # Preserve all previous frontend response keys.
                "detection_id": record.get("detection_id", record.get("id")),
                "event_id": event_id,
                "timestamp": (
                    record.get("timestamp")
                    or record.get("detected_at")
                    or record.get("created_at")
                    or event_fields.get("timestamp")
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
