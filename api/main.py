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
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================================================================
# PERSISTENT WORKFLOW
# ================================================================

workflow = PersistentSOCWorkflow(
    simulation_mode=True
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


# ================================================================
# HELPERS
# ================================================================

def now_iso():

    return datetime.now(
        timezone.utc
    ).isoformat()


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
def endpoint_overview():

    return {

        "status":
            "HEALTHY",

        "timestamp":
            now_iso(),

        "simulation_mode":
            True,

        "real_response_execution":
            False,

        "collectors": {

            "process":
                "ACTIVE",

            "file":
                "ACTIVE",

            "network":
                "ACTIVE",

            "registry":
                "ACTIVE",
        },

        "event_count":
            0,

        "detection_count":
            0,

        "events":
            [],

        "detections":
            [],
    }


# ================================================================
# DASHBOARD SUMMARY
# ================================================================

@app.get(
    "/api/v1/dashboard/summary"
)
def dashboard_summary():

    cases = workflow.list_cases(
        limit=1000
    )


    tickets = ticket_store.list_tickets(
        limit=1000
    )


    actions = workflow.action_store.list_actions(
        limit=1000
    )


    p1 = sum(
        1
        for ticket in tickets
        if ticket.get("priority") == "P1"
    )


    p2 = sum(
        1
        for ticket in tickets
        if ticket.get("priority") == "P2"
    )


    p3 = sum(
        1
        for ticket in tickets
        if ticket.get("priority") == "P3"
    )


    p4 = sum(
        1
        for ticket in tickets
        if ticket.get("priority") == "P4"
    )


    pending_approvals = sum(
        1
        for ticket in tickets
        if ticket.get(
            "approval_status"
        ) == "PENDING"
    )


    approved_tickets = sum(
        1
        for ticket in tickets
        if ticket.get(
            "approval_status"
        ) == "APPROVED"
    )


    rejected_tickets = sum(
        1
        for ticket in tickets
        if ticket.get(
            "approval_status"
        ) == "REJECTED"
    )


    open_tickets = sum(
        1
        for ticket in tickets
        if ticket.get(
            "status"
        )
        not in {
            "CLOSED",
            "RESOLVED",
            "REJECTED",
        }
    )


    pending_cases = sum(
        1
        for case in cases
        if case.get(
            "case_status"
        )
        == "AWAITING_ANALYST_REVIEW"
    )


    critical_cases = sum(
        1
        for case in cases
        if case.get(
            "risk_level"
        )
        == "CRITICAL"
    )


    high_cases = sum(
        1
        for case in cases
        if case.get(
            "risk_level"
        )
        == "HIGH"
    )


    ready_actions = sum(
        1
        for action in actions
        if action.execution_status
        == "READY"
    )


    pending_actions = sum(
        1
        for action in actions
        if action.approval_status
        == "PENDING"
    )


    return {

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

        "total_response_actions":
            len(
                actions
            ),

        "pending_response_actions":
            pending_actions,

        "ready_response_actions":
            ready_actions,

        "priority_counts": {

            "P1":
                p1,

            "P2":
                p2,

            "P3":
                p3,

            "P4":
                p4,
        },

        "simulation_mode":
            True,

        "persistent_recovery":
            True,

        "real_response_execution":
            False,
    }


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