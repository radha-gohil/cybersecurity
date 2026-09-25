from typing import Any
from datetime import datetime, timezone

from fastapi import (
    FastAPI,
    HTTPException,
)

from fastapi.middleware.cors import (
    CORSMiddleware,
)

from pydantic import (
    BaseModel,
    Field,
)

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)

from response.incident_view_service import (
    IncidentViewService,
)

from response.soc_query_service import (
    SOCQueryService,
)

from response.backend_integrity_service import (
    BackendIntegrityService,
)

from detection.fusion.incident_store import (
    IncidentStore,
)

from agents.multi_agent_pipeline import (
    MultiAgentSecurityPipeline,
)

from endpoint.storage.database import (
    get_endpoint_database_summary,
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
)


# ================================================================
# CORS
# ================================================================

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

    allow_methods=[
        "*"
    ],

    allow_headers=[
        "*"
    ],
)


# ================================================================
# PERSISTENT WORKFLOW
# ================================================================

workflow = PersistentSOCWorkflow(
    simulation_mode=True
)


# ================================================================
# DETECTION / CORRELATION INCIDENT STORE
# ================================================================

detected_incident_store = (
    IncidentStore()
)


# ================================================================
# MULTI-AGENT SECURITY PIPELINE
# ================================================================

multi_agent_pipeline = (
    MultiAgentSecurityPipeline(
        autonomy_level=2
    )
)


# ================================================================
# TICKET STORE
# ================================================================

ticket_store = SOCTicketStore()


# ================================================================
# INCIDENT VIEW SERVICE
# ================================================================

incident_view_service = IncidentViewService(
    workflow=workflow,
    ticket_store=ticket_store,
)


# ================================================================
# SOC QUERY SERVICE
# ================================================================

query_service = SOCQueryService(
    case_store=workflow.case_store,
    ticket_store=ticket_store,
    action_store=workflow.action_store,
)


# ================================================================
# BACKEND INTEGRITY SERVICE
# ================================================================

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

    incident_id: str = Field(
        ...,
        min_length=1,
    )

    intelligence: dict


class AnalystDecisionRequest(BaseModel):

    analyst: str = Field(
        ...,
        min_length=1,
    )

    comment: str = ""


class AnalystRejectionRequest(BaseModel):

    analyst: str = Field(
        ...,
        min_length=1,
    )

    reason: str = Field(
        ...,
        min_length=1,
    )


class MitigationVerificationRequest(BaseModel):

    before_state: dict

    simulated_after_state: dict

    response_result: dict


# ================================================================
# HELPERS
# ================================================================

def now_iso():

    return datetime.now(
        timezone.utc
    ).isoformat()


# ================================================================
# ENRICH DETECTED INCIDENT
# ================================================================

def enrich_detected_incident(
    incident: dict,
):

    if not isinstance(
        incident,
        dict,
    ):

        return {}


    incident_id = (
        incident.get(
            "incident_id"
        )
    )


    soc_case = None


    if incident_id:

        try:

            soc_case = (
                workflow.recover_case(
                    incident_id
                )
            )

        except Exception:

            soc_case = None


    soc_case_exists = (
        soc_case is not None
    )


    soc_case_status = None

    approval_status = None

    ticket_id = None

    ticket_priority = None

    selected_plan = None

    residual_risk = None

    mitigation_status = (
        "NOT_VERIFIED"
    )


    if soc_case_exists:

        soc_case_status = (
            soc_case.get(
                "status"
            )
        )


        ticket_data = (
            soc_case.get(
                "ticket_data"
            )
            or {}
        )


        if isinstance(
            ticket_data,
            dict,
        ):

            approval_status = (
                ticket_data.get(
                    "approval_status"
                )
            )

            ticket_id = (
                ticket_data.get(
                    "ticket_id"
                )
            )

            ticket_priority = (
                ticket_data.get(
                    "priority"
                )
            )


        decision = (
            soc_case.get(
                "decision"
            )
            or {}
        )


        if isinstance(
            decision,
            dict,
        ):

            selected_plan = (
                decision.get(
                    "selected_plan_name"
                )
                or
                decision.get(
                    "selected_plan"
                )
                or
                decision.get(
                    "plan_name"
                )
            )


            residual_risk = (
                decision.get(
                    "predicted_residual_risk"
                )
                or
                decision.get(
                    "residual_risk"
                )
            )


        mitigation = (
            soc_case.get(
                "mitigation_verification"
            )
            or {}
        )


        if isinstance(
            mitigation,
            dict,
        ):

            mitigation_status = (
                mitigation.get(
                    "status"
                )
                or
                "NOT_VERIFIED"
            )


    return {

        **incident,

        "record_type":
            "DETECTED_INCIDENT",

        "soc_case_exists":
            soc_case_exists,

        "soc_case_status":
            soc_case_status,

        "approval_status":
            approval_status,

        "ticket_id":
            ticket_id,

        "ticket_priority":
            ticket_priority,

        "selected_plan":
            selected_plan,

        "residual_risk":
            residual_risk,

        "mitigation_status":
            mitigation_status,

        "simulation_mode":
            True,

        "real_response_executed":
            False,
    }


def serialize_value(
    value: Any,
):

    if value is None:

        return None


    if isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):

        return value


    if isinstance(
        value,
        dict,
    ):

        return {

            str(key):
                serialize_value(
                    item
                )

            for key, item
            in value.items()
        }


    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):

        return [

            serialize_value(
                item
            )

            for item in value
        ]


    if hasattr(
        value,
        "to_dict",
    ):

        return serialize_value(
            value.to_dict()
        )


    return str(
        value
    )


def require_case(
    incident_id: str,
):

    case = workflow.recover_case(
        incident_id
    )


    if case is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"SOC case not found for "
                f"incident {incident_id}."
            ),
        )


    return case


# ================================================================
# ROOT
# ================================================================

@app.get("/")
def root():

    return {

        "product":
            "SENTINEL-X",

        "service":
            "Persistent SOC Backend API",

        "version":
            "1.4.0",

        "status":
            "RUNNING",

        "simulation_mode":
            True,

        "persistent_recovery":
            True,

        "evidence_persistence":
            True,

        "timeline_persistence":
            True,

        "soc_query_layer":
            True,

        "backend_integrity":
            True,

        "real_response_execution":
            False,
    }


# ================================================================
# HEALTH
# ================================================================

@app.get(
    "/api/v1/health"
)
def health():

    return {

        "status":
            "HEALTHY",

        "service":
            "SENTINEL-X SOC API",

        "version":
            "1.4.0",

        "timestamp":
            now_iso(),

        "simulation_mode":
            True,

        "persistent_recovery":
            True,

        "evidence_persistence":
            True,

        "timeline_persistence":
            True,

        "soc_query_layer":
            True,

        "backend_integrity":
            True,

        "real_response_execution":
            False,
    }


# ================================================================
# ENDPOINT MONITORING
# ================================================================

@app.get(
    "/api/v1/endpoint/overview"
)
def endpoint_overview(
    limit: int = 50,
):

    limit = max(
        1,
        min(
            limit,
            200,
        ),
    )


    try:

        # --------------------------------------------------------
        # REAL STORED ENDPOINT DATA
        # --------------------------------------------------------

        endpoint_data = (
            get_endpoint_database_summary(
                recent_limit=limit
            )
        )


        # --------------------------------------------------------
        # CORRELATED INCIDENT INFORMATION
        # --------------------------------------------------------

        detected_incidents = (
            detected_incident_store
            .get_incidents()
        )


        if not isinstance(
            detected_incidents,
            list,
        ):

            detected_incidents = []


        # --------------------------------------------------------
        # CHECK WHICH DETECTED INCIDENTS HAVE ENTERED SOC
        # --------------------------------------------------------

        promoted_incident_count = 0


        for incident in detected_incidents:

            incident_id = (

                incident.get(
                    "incident_id"
                )

                if isinstance(
                    incident,
                    dict,
                )

                else None
            )


            if not incident_id:

                continue


            try:

                existing_case = (
                    workflow.recover_case(
                        incident_id
                    )
                )


                if existing_case is not None:

                    promoted_incident_count += 1


            except Exception:

                # Do not break endpoint telemetry if a single
                # SOC recovery lookup fails.
                continue


        incident_count = len(
            detected_incidents
        )


        awaiting_investigation_count = max(

            0,

            incident_count
            - promoted_incident_count,
        )


        # --------------------------------------------------------
        # RESPONSE
        # --------------------------------------------------------

        return {

            "status":
                "HEALTHY",

            "timestamp":
                now_iso(),

            "data_source":
                "ENDPOINT_SQLITE_DATABASE",

            "simulation_mode":
                True,

            "real_response_execution":
                False,


            # ----------------------------------------------------
            # COLLECTOR RUNTIME
            #
            # IMPORTANT:
            # FastAPI does not currently launch the collector
            # processes. Therefore we must not falsely say ACTIVE.
            # ----------------------------------------------------

            "collector_runtime_tracking":
                False,

            "live_collection_started_by_api":
                False,

            "collectors": {

                "process":
                    "CONFIGURED",

                "file":
                    "CONFIGURED",

                "network":
                    "CONFIGURED",

                "registry":
                    "CONFIGURED",
            },

            "collector_note": (

                "Collector modules are configured, but this "
                "FastAPI process does not start or heartbeat-monitor "
                "them. Telemetry and detections shown below are read "
                "from the persisted endpoint SQLite database."
            ),


            # ----------------------------------------------------
            # STORED TELEMETRY
            # ----------------------------------------------------

            "event_count":
                endpoint_data.get(
                    "event_count",
                    0,
                ),

            "detection_count":
                endpoint_data.get(
                    "detection_count",
                    0,
                ),


            # ----------------------------------------------------
            # INCIDENTS
            # ----------------------------------------------------

            "incident_count":
                incident_count,

            "promoted_incident_count":
                promoted_incident_count,

            "awaiting_investigation_count":
                awaiting_investigation_count,


            # ----------------------------------------------------
            # EVENT ANALYTICS
            # ----------------------------------------------------

            "event_category_counts":
                endpoint_data.get(
                    "event_category_counts",
                    {},
                ),

            "event_severity_counts":
                endpoint_data.get(
                    "event_severity_counts",
                    {},
                ),


            # ----------------------------------------------------
            # DETECTION ANALYTICS
            # ----------------------------------------------------

            "detection_severity_counts":
                endpoint_data.get(
                    "detection_severity_counts",
                    {},
                ),

            "detection_engine_counts":
                endpoint_data.get(
                    "detection_engine_counts",
                    {},
                ),

            "detection_type_counts":
                endpoint_data.get(
                    "detection_type_counts",
                    {},
                ),


            # ----------------------------------------------------
            # RECENT REAL STORED DATA
            # ----------------------------------------------------

            "events":
                serialize_value(
                    endpoint_data.get(
                        "events",
                        [],
                    )
                ),

            "detections":
                serialize_value(
                    endpoint_data.get(
                        "detections",
                        [],
                    )
                ),

            "recent_limit":
                limit,
        }


    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Failed to load endpoint overview: "
                f"{error}"
            ),
        )

# ================================================================
# DASHBOARD SUMMARY
# ================================================================

@app.get(
    "/api/v1/dashboard/summary"
)
def dashboard_summary():

    try:

        # ========================================================
        # PERSISTENT SOC DATA
        # ========================================================

        cases = (
            workflow.list_cases(
                limit=1000
            )
            or []
        )


        tickets = (
            ticket_store.list_tickets(
                limit=1000
            )
            or []
        )


        actions = (
            workflow.action_store.list_actions(
                limit=1000
            )
            or []
        )


        # ========================================================
        # REAL ENDPOINT DATABASE DATA
        # ========================================================

        endpoint_data = (
            get_endpoint_database_summary(
                recent_limit=1
            )
        )


        # ========================================================
        # DETECTED / CORRELATED INCIDENTS
        # ========================================================

        detected_incidents = (
            detected_incident_store
            .get_incidents()
        )


        if not isinstance(
            detected_incidents,
            list,
        ):

            detected_incidents = []


        # ========================================================
        # SAFE VALUE HELPER
        # ========================================================

        def get_value(
            item,
            key,
            default=None,
        ):

            if isinstance(
                item,
                dict,
            ):

                return item.get(
                    key,
                    default,
                )


            return getattr(
                item,
                key,
                default,
            )


        # ========================================================
        # CASE ID SET
        # ========================================================

        soc_case_ids = set()


        for case in cases:

            incident_id = get_value(
                case,
                "incident_id",
            )


            if incident_id:

                soc_case_ids.add(
                    str(
                        incident_id
                    )
                )


        # ========================================================
        # DETECTED INCIDENT COUNTS
        # ========================================================

        promoted_incident_count = 0


        for incident in detected_incidents:

            incident_id = get_value(
                incident,
                "incident_id",
            )


            if (
                incident_id
                and str(
                    incident_id
                ) in soc_case_ids
            ):

                promoted_incident_count += 1


        detected_incident_count = len(
            detected_incidents
        )


        awaiting_investigation_count = max(

            0,

            detected_incident_count
            - promoted_incident_count,
        )


        # ========================================================
        # DETECTED INCIDENT SEVERITY
        # ========================================================

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


            if severity not in (
                incident_severity_counts
            ):

                severity = "UNKNOWN"


            incident_severity_counts[
                severity
            ] += 1


        # ========================================================
        # TICKET PRIORITY COUNTS
        # ========================================================

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


            if priority not in (
                priority_counts
            ):

                priority = "P4"


            priority_counts[
                priority
            ] += 1


        # ========================================================
        # TICKET APPROVAL COUNTS
        # ========================================================

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


            if (
                approval_status
                == "PENDING"
            ):

                pending_approvals += 1


            elif (
                approval_status
                == "APPROVED"
            ):

                approved_tickets += 1


            elif (
                approval_status
                == "REJECTED"
            ):

                rejected_tickets += 1


            if ticket_status not in {

                "CLOSED",
                "RESOLVED",
                "REJECTED",

            }:

                open_tickets += 1


        # ========================================================
        # SOC CASE COUNTS
        # ========================================================

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

            case_status = (

                get_value(
                    case,
                    "case_status",
                )

                or get_value(
                    case,
                    "status",
                    "",
                )

                or ""
            )


            case_status = str(
                case_status
            ).upper()


            if (
                case_status
                == "AWAITING_ANALYST_REVIEW"
            ):

                pending_cases += 1


            # ----------------------------------------------------
            # RISK
            # ----------------------------------------------------

            risk_level = get_value(
                case,
                "risk_level",
            )


            ticket_data = get_value(
                case,
                "ticket_data",
                {},
            )


            if (
                not risk_level
                and isinstance(
                    ticket_data,
                    dict,
                )
            ):

                risk_level = (
                    ticket_data.get(
                        "risk_level"
                    )
                )


            risk_level = str(

                risk_level
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


            # ----------------------------------------------------
            # MITIGATION
            # ----------------------------------------------------

            mitigation_status = (
                get_value(
                    case,
                    "mitigation_status",
                )
            )


            mitigation_verification = (
                get_value(
                    case,
                    "mitigation_verification",
                )
            )


            if (
                not mitigation_status
                and isinstance(
                    mitigation_verification,
                    dict,
                )
            ):

                mitigation_status = (

                    mitigation_verification.get(
                        "status"
                    )

                    or mitigation_verification.get(
                        "verification_status"
                    )
                )


            mitigation_status = str(

                mitigation_status
                or "NOT_VERIFIED"

            ).upper()


            if (
                mitigation_status
                in {
                    "VERIFIED",
                    "MITIGATION_VERIFIED",
                }
            ):

                mitigation_key = (
                    "VERIFIED"
                )


            elif (
                mitigation_status
                in {
                    "PARTIAL",
                    "PARTIALLY_VERIFIED",
                    "PARTIAL_SUCCESS",
                }
            ):

                mitigation_key = (
                    "PARTIAL"
                )


            elif (
                mitigation_status
                in {
                    "FAILED",
                    "MITIGATION_FAILED",
                }
            ):

                mitigation_key = (
                    "FAILED"
                )


            elif (
                mitigation_status
                in {
                    "NOT_VERIFIED",
                    "PENDING",
                    "NOT_RUN",
                }
            ):

                mitigation_key = (
                    "NOT_VERIFIED"
                )


            else:

                mitigation_key = (
                    "UNKNOWN"
                )


            mitigation_status_counts[
                mitigation_key
            ] += 1


        # ========================================================
        # RESPONSE ACTION COUNTS
        # ========================================================

        ready_actions = 0

        pending_actions = 0


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


            if (
                execution_status
                == "READY"
            ):

                ready_actions += 1


            if (
                approval_status
                == "PENDING"
            ):

                pending_actions += 1


        # ========================================================
        # ENDPOINT DATABASE COUNTS
        # ========================================================

        event_count = int(

            endpoint_data.get(
                "event_count",
                0,
            )

            or 0
        )


        detection_count = int(

            endpoint_data.get(
                "detection_count",
                0,
            )

            or 0
        )


        event_category_counts = (

            endpoint_data.get(
                "event_category_counts",
                {},
            )

            or {}
        )


        event_severity_counts = (

            endpoint_data.get(
                "event_severity_counts",
                {},
            )

            or {}
        )


        detection_severity_counts = (

            endpoint_data.get(
                "detection_severity_counts",
                {},
            )

            or {}
        )


        detection_engine_counts = (

            endpoint_data.get(
                "detection_engine_counts",
                {},
            )

            or {}
        )


        detection_type_counts = (

            endpoint_data.get(
                "detection_type_counts",
                {},
            )

            or {}
        )


        # ========================================================
        # COMPLETE DASHBOARD RESPONSE
        #
        # IMPORTANT:
        # Existing keys are preserved for SOCDashboard.jsx.
        # New telemetry / detection keys are added for Dashboard.jsx.
        # ========================================================

        return {

            # ----------------------------------------------------
            # TIMESTAMP / SOURCE
            # ----------------------------------------------------

            "timestamp":
                now_iso(),

            "data_source":
                "ENDPOINT_SQLITE_DATABASE",


            # ----------------------------------------------------
            # ENDPOINT TELEMETRY
            # ----------------------------------------------------

            "event_count":
                event_count,

            "detection_count":
                detection_count,

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


            # ----------------------------------------------------
            # DETECTION / CORRELATION
            # ----------------------------------------------------

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


            # ----------------------------------------------------
            # PERSISTENT SOC CASES
            # Existing fields retained.
            # ----------------------------------------------------

            "persistent_soc_cases":
                len(
                    cases
                ),

            "pending_soc_cases":
                pending_cases,

            "critical_cases":
                critical_cases,

            "high_cases":
                high_cases,

            "medium_cases":
                medium_cases,

            "low_cases":
                low_cases,

            "info_cases":
                info_cases,


            # ----------------------------------------------------
            # TICKETS
            # ----------------------------------------------------

            "total_tickets":
                len(
                    tickets
                ),

            "open_tickets":
                open_tickets,

            "pending_approvals":
                pending_approvals,

            "approved_tickets":
                approved_tickets,

            "rejected_tickets":
                rejected_tickets,

            "priority_counts":
                priority_counts,


            # ----------------------------------------------------
            # RESPONSE ACTIONS
            # ----------------------------------------------------

            "total_response_actions":
                len(
                    actions
                ),

            "pending_response_actions":
                pending_actions,

            "ready_response_actions":
                ready_actions,


            # ----------------------------------------------------
            # MITIGATION
            # ----------------------------------------------------

            "mitigation_status_counts":
                mitigation_status_counts,

            "verified_mitigations":
                mitigation_status_counts[
                    "VERIFIED"
                ],

            "partial_mitigations":
                mitigation_status_counts[
                    "PARTIAL"
                ],

            "failed_mitigations":
                mitigation_status_counts[
                    "FAILED"
                ],

            "not_verified_mitigations":
                mitigation_status_counts[
                    "NOT_VERIFIED"
                ],


            # ----------------------------------------------------
            # PLATFORM SAFETY
            # ----------------------------------------------------

            "simulation_mode":
                True,

            "persistent_recovery":
                True,

            "real_response_execution":
                False,

            "collector_runtime_tracking":
                False,

            "live_collection_started_by_api":
                False,
        }


    except HTTPException:

        raise


    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(

                "Failed to load dashboard summary: "
                f"{error}"
            ),
        )


# ================================================================
# CREATE SOC CASE
# ================================================================

@app.post(
    "/api/v1/cases"
)
def create_case(
    request: CreateCaseRequest,
):

    incident_id = request.incident_id.strip()


    if not incident_id:

        raise HTTPException(
            status_code=400,
            detail=(
                "incident_id cannot be empty."
            ),
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

            "success":
                True,

            "incident_id":
                incident_id,

            "status":
                case.get(
                    "status"
                ),

            "ticket":
                serialize_value(
                    case.get(
                        "ticket_data"
                    )
                ),

            "response_action_count":
                case.get(
                    "response_action_count",
                    0,
                ),

            "digital_twin_decision":
                serialize_value(
                    case.get(
                        "decision"
                    )
                ),

            "explanation":
                serialize_value(
                    case.get(
                        "explanation"
                    )
                ),

            "response_actions":
                serialize_value(
                    case.get(
                        "response_actions"
                    )
                ),

            "evidence":
                serialize_value(
                    case.get(
                        "evidence",
                        {},
                    )
                ),

            "timeline":
                serialize_value(
                    case.get(
                        "timeline",
                        [],
                    )
                ),

            "persistence":
                serialize_value(
                    case.get(
                        "persistence"
                    )
                ),

            "simulation_mode":
                True,

            "persistent_recovery":
                True,

            "real_response_executed":
                False,
        }


    except HTTPException:

        raise


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
                f"Failed to create SOC case: "
                f"{error}"
            ),
        )


# ================================================================
# LIST CASES
# ================================================================

@app.get(
    "/api/v1/cases"
)
def list_cases(
    limit: int = 100,
):

    limit = max(
        1,
        min(
            limit,
            1000,
        ),
    )


    cases = workflow.list_cases(
        limit=limit
    )


    return {

        "count":
            len(
                cases
            ),

        "persistent":
            True,

        "cases":
            serialize_value(
                cases
            ),
    }


# ================================================================
# LIST DETECTED / CORRELATED INCIDENTS
# ================================================================

@app.get(
    "/api/v1/detected-incidents"
)
def list_detected_incidents(
    limit: int = 100,
):

    limit = max(
        1,
        min(
            limit,
            1000,
        ),
    )


    try:

        incidents = (
            detected_incident_store
            .get_incidents()
        )


        incidents = (
            incidents[
                :limit
            ]
        )


        enriched_incidents = [

            enrich_detected_incident(
                incident
            )

            for incident
            in incidents
        ]


        return {

            "count":
                len(
                    enriched_incidents
                ),

            "source":
                "CORRELATION_INCIDENT_STORE",

            "persistent":
                True,

            "incidents":
                serialize_value(
                    enriched_incidents
                ),

            "simulation_mode":
                True,

            "real_response_executed":
                False,
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
# GET ONE DETECTED / CORRELATED INCIDENT
# ================================================================

@app.get(
    "/api/v1/detected-incidents/{incident_id}"
)
def get_detected_incident(
    incident_id: str,
):

    try:

        incident = (
            detected_incident_store
            .get_incident(
                incident_id
            )
        )


        if incident is None:

            raise HTTPException(

                status_code=404,

                detail=(
                    f"Detected incident "
                    f"{incident_id} "
                    "was not found."
                ),
            )


        return (
            enrich_detected_incident(
                incident
            )
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
# INVESTIGATE / PROMOTE DETECTED INCIDENT INTO PERSISTENT SOC
# ================================================================

@app.post(
    "/api/v1/detected-incidents/{incident_id}/investigate"
)
def investigate_detected_incident(
    incident_id: str,
):

    incident_id = (
        incident_id.strip()
    )


    if not incident_id:

        raise HTTPException(
            status_code=400,
            detail=(
                "incident_id cannot be empty."
            ),
        )


    try:

        incident = (
            detected_incident_store
            .get_incident(
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
                f"Detected incident "
                f"{incident_id} "
                "was not found."
            ),
        )


    existing = (
        workflow.recover_case(
            incident_id
        )
    )


    if existing is not None:

        return {

            "success":
                True,

            "already_in_soc":
                True,

            "incident_id":
                incident_id,

            "status":
                existing.get(
                    "status"
                ),

            "ticket":
                serialize_value(
                    existing.get(
                        "ticket_data",
                        {},
                    )
                ),

            "response_action_count":
                existing.get(
                    "response_action_count",
                    0,
                ),

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }


    try:

        intelligence = (
            multi_agent_pipeline
            .process_incident(
                incident
            )
        )


        if not isinstance(
            intelligence,
            dict,
        ):

            raise ValueError(
                "Multi-agent pipeline returned "
                "an invalid intelligence result."
            )


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
            intelligence.get(
                "status",
                "UNKNOWN",
            )
        ).upper()


        if pipeline_status == "INCOMPLETE":

            raise ValueError(
                "Multi-agent investigation "
                "completed with an INCOMPLETE status."
            )


        case = (
            workflow.create_case(
                incident_id=
                    incident_id,

                intelligence=
                    intelligence,
            )
        )


        return {

            "success":
                True,

            "already_in_soc":
                False,

            "incident_id":
                incident_id,

            "detected_incident":
                serialize_value(
                    incident
                ),

            "multi_agent": {

                "status":
                    intelligence.get(
                        "status"
                    ),

                "security_state":
                    intelligence.get(
                        "security_state"
                    ),

                "risk_score":
                    intelligence.get(
                        "risk_score",
                        0,
                    ),

                "risk_level":
                    intelligence.get(
                        "risk_level",
                        "INFO",
                    ),

                "final_decision":
                    intelligence.get(
                        "final_decision",
                        "MONITOR",
                    ),

                "autonomy_level":
                    intelligence.get(
                        "autonomy_level"
                    ),

                "autonomy_mode":
                    intelligence.get(
                        "autonomy_mode"
                    ),

                "execution_enabled":
                    intelligence.get(
                        "execution_enabled",
                        False,
                    ),
            },

            "intelligence":
                serialize_value(
                    intelligence
                ),

            "status":
                case.get(
                    "status"
                ),

            "ticket":
                serialize_value(
                    case.get(
                        "ticket_data",
                        {},
                    )
                ),

            "response_action_count":
                case.get(
                    "response_action_count",
                    0,
                ),

            "digital_twin_decision":
                serialize_value(
                    case.get(
                        "decision",
                        {},
                    )
                ),

            "explanation":
                serialize_value(
                    case.get(
                        "explanation",
                        {},
                    )
                ),

            "persistence":
                serialize_value(
                    case.get(
                        "persistence",
                        {},
                    )
                ),

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }


    except HTTPException:

        raise


    except ValueError as error:

        raise HTTPException(
            status_code=422,
            detail=str(
                error
            ),
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
# GET CASE
# ================================================================

@app.get(
    "/api/v1/cases/{incident_id}"
)
def get_case(
    incident_id: str,
):

    case = require_case(
        incident_id
    )


    return {

        "incident_id":
            incident_id,

        "status":
            case.get(
                "status"
            ),

        "ticket":
            serialize_value(
                case.get(
                    "ticket_data"
                )
            ),

        "decision":
            serialize_value(
                case.get(
                    "decision"
                )
            ),

        "explanation":
            serialize_value(
                case.get(
                    "explanation"
                )
            ),

        "response_actions":
            serialize_value(
                case.get(
                    "response_actions"
                )
            ),

        "response_action_count":
            case.get(
                "response_action_count",
                0,
            ),

        "evidence":
            serialize_value(
                case.get(
                    "evidence",
                    {},
                )
            ),

        "timeline":
            serialize_value(
                case.get(
                    "timeline",
                    [],
                )
            ),

        "recovered_from_database":
            case.get(
                "recovered_from_database",
                False,
            ),

        "simulation_mode":
            True,

        "real_response_executed":
            False,
    }


# ================================================================
# GET MITIGATION VERIFICATION
# ================================================================

@app.get(
    "/api/v1/cases/{incident_id}/mitigation-verification"
)
def get_mitigation_verification(
    incident_id: str,
):

    require_case(
        incident_id
    )


    verification = (
        workflow.get_mitigation_verification(
            incident_id
        )
    )


    if not verification:

        return {

            "incident_id":
                incident_id,

            "status":
                "NOT_VERIFIED",

            "verified":
                False,

            "verification":
                {},

            "persistent":
                True,

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }


    return {

        "incident_id":
            incident_id,

        "status":
            verification.get(
                "status"
            ),

        "verified":
            True,

        "verification":
            serialize_value(
                verification
            ),

        "persistent":
            True,

        "simulation_mode":
            True,

        "real_response_executed":
            False,
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

    require_case(
        incident_id
    )


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

                incident_id=
                    incident_id,

                before_state=
                    request.before_state,

                simulated_after_state=
                    request.simulated_after_state,

                response_result=
                    request.response_result,
            )
        )


        return {

            "success":
                result.get(
                    "success",
                    False,
                ),

            "incident_id":
                incident_id,

            "status":
                result.get(
                    "status"
                ),

            "verification":
                serialize_value(
                    result.get(
                        "verification",
                        {},
                    )
                ),

            "persisted":
                result.get(
                    "persisted",
                    False,
                ),

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }


    except TypeError as error:

        raise HTTPException(
            status_code=400,
            detail=str(
                error
            ),
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
def get_digital_twin(
    incident_id: str,
):

    case = require_case(
        incident_id
    )


    return {

        "incident_id":
            incident_id,

        "decision":
            serialize_value(
                case.get(
                    "decision"
                )
            ),

        "explanation":
            serialize_value(
                case.get(
                    "explanation"
                )
            ),

        "recovered_from_database":
            case.get(
                "recovered_from_database",
                False,
            ),

        "simulation_mode":
            True,

        "real_endpoint_modified":
            False,
    }


# ================================================================
# RESPONSE ACTIONS
# ================================================================

@app.get(
    "/api/v1/cases/{incident_id}/responses"
)
def get_response_actions(
    incident_id: str,
):

    require_case(
        incident_id
    )


    actions = workflow.get_response_actions(
        incident_id
    )


    return {

        "incident_id":
            incident_id,

        "count":
            len(
                actions
            ),

        "actions":
            serialize_value(
                actions
            ),

        "persistent":
            True,

        "simulation_mode":
            True,

        "real_response_executed":
            False,
    }


# ================================================================
# INCIDENT EVIDENCE
# ================================================================

@app.get(
    "/api/v1/cases/{incident_id}/evidence"
)
def get_case_evidence(
    incident_id: str,
):

    require_case(
        incident_id
    )


    evidence = workflow.get_evidence(
        incident_id
    )


    return {

        "incident_id":
            incident_id,

        "persistent":
            True,

        "evidence":
            serialize_value(
                evidence
            ),
    }


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


    timeline = workflow.get_timeline(
        incident_id
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
# APPROVE CASE
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

        result = workflow.approve_case(
            incident_id=incident_id,
            analyst=request.analyst,
            comment=request.comment,
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
                f"Approval workflow failed: "
                f"{error}"
            ),
        )


# ================================================================
# REJECT CASE
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

        result = workflow.reject_case(
            incident_id=incident_id,
            analyst=request.analyst,
            reason=request.reason,
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
                f"Rejection workflow failed: "
                f"{error}"
            ),
        )


# ================================================================
# LIST ALL TICKETS
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


    tickets = ticket_store.list_tickets(
        limit=limit
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
# GET TICKET
# ================================================================

@app.get(
    "/api/v1/tickets/{ticket_id}"
)
def get_ticket(
    ticket_id: str,
):

    ticket = ticket_store.get_ticket(
        ticket_id
    )


    if ticket is None:

        raise HTTPException(
            status_code=404,
            detail=(
                f"Ticket {ticket_id} "
                f"not found."
            ),
        )


    return serialize_value(
        ticket
    )


# ================================================================
# INCIDENT TICKETS
# ================================================================

@app.get(
    "/api/v1/incidents/{incident_id}/tickets"
)
def get_incident_tickets(
    incident_id: str,
):

    tickets = ticket_store.get_by_incident(
        incident_id
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

    result = incident_view_service.get_full_incident(
        incident_id
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


# ================================================================
# INCIDENT SEARCH
# ================================================================

@app.get(
    "/api/v1/search/incidents"
)
def search_incidents(
    risk_level: str = None,
    status: str = None,
    min_risk: float = None,
    max_risk: float = None,
    limit: int = 100,
):

    try:

        return query_service.search_incidents(
            risk_level=risk_level,
            status=status,
            min_risk=min_risk,
            max_risk=max_risk,
            limit=limit,
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Incident search failed: "
                f"{error}"
            ),
        )


# ================================================================
# TICKET SEARCH
# ================================================================

@app.get(
    "/api/v1/search/tickets"
)
def search_tickets(
    priority: str = None,
    status: str = None,
    approval_status: str = None,
    incident_id: str = None,
    limit: int = 100,
):

    try:

        return query_service.search_tickets(
            priority=priority,
            status=status,
            approval_status=approval_status,
            incident_id=incident_id,
            limit=limit,
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Ticket search failed: "
                f"{error}"
            ),
        )


# ================================================================
# RESPONSE ACTION SEARCH
# ================================================================

@app.get(
    "/api/v1/search/actions"
)
def search_actions(
    incident_id: str = None,
    action_type: str = None,
    approval_status: str = None,
    execution_status: str = None,
    risk_level: str = None,
    limit: int = 100,
):

    try:

        return query_service.search_actions(
            incident_id=incident_id,
            action_type=action_type,
            approval_status=approval_status,
            execution_status=execution_status,
            risk_level=risk_level,
            limit=limit,
        )


    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Response action search failed: "
                f"{error}"
            ),
        )


# ================================================================
# BACKEND INTEGRITY - SINGLE INCIDENT
# ================================================================

@app.get(
    "/api/v1/integrity/incidents/{incident_id}"
)
def check_incident_integrity(
    incident_id: str,
):

    result = integrity_service.check_incident(
        incident_id
    )


    if (
        result.get(
            "case_found"
        )
        is False
    ):

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


# ================================================================
# BACKEND INTEGRITY - ALL INCIDENTS
# ================================================================

@app.get(
    "/api/v1/integrity"
)
def check_backend_integrity(
    limit: int = 1000,
):

    limit = max(
        1,
        min(
            limit,
            5000,
        ),
    )


    result = integrity_service.check_all(
        limit=limit
    )


    return serialize_value(
        result
    )