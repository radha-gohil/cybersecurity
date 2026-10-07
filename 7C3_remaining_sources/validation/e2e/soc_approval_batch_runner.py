from __future__ import annotations

import csv
import json
import os
import uuid

from pathlib import Path

from urllib.error import (
    HTTPError,
    URLError,
)

from urllib.request import (
    Request,
    urlopen,
)


from config import (
    ACTIVE_SOC_DATABASE_PATH,
    VALIDATION_DATABASE_PATH,
    IS_VALIDATION_MODE,
)

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)


# ================================================================
# CONFIG
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

REPORT_DIR = (
    PROJECT_ROOT
    / "validation"
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

CSV_PATH = (
    REPORT_DIR
    / "soc_approval_validation.csv"
)

JSON_PATH = (
    REPORT_DIR
    / "soc_approval_validation.json"
)

API_BASE = (
    os.getenv(
        "SENTINEL_API_BASE_URL",
        "http://127.0.0.1:8003",
    )
    .rstrip("/")
)


# ================================================================
# HELPERS
# ================================================================

def safe_dict(value):

    if isinstance(
        value,
        dict,
    ):
        return value

    return {}


def safe_list(value):

    if isinstance(
        value,
        list,
    ):
        return value

    return []


def normalize_path(value):

    return (
        Path(value)
        .resolve()
    )


def add_result(
    results,
    scenario_id,
    scenario_name,
    observed,
    expected,
    passed,
    failure_layers="",
    notes="",
):

    results.append(
        {
            "scenario_id":
                scenario_id,

            "family":
                "SOC_APPROVAL_E2E",

            "scenario_name":
                scenario_name,

            "observed":
                observed,

            "expected":
                expected,

            "failure_layers":
                failure_layers,

            "passed":
                bool(
                    passed
                ),

            "notes":
                notes,
        }
    )


# ================================================================
# HTTP
# ================================================================

def api_request(
    method,
    path,
    body=None,
    timeout=30,
):

    url = (
        API_BASE
        + path
    )

    payload = None

    headers = {
        "Accept":
            "application/json",
    }

    if body is not None:

        payload = (
            json.dumps(
                body
            )
            .encode(
                "utf-8"
            )
        )

        headers[
            "Content-Type"
        ] = "application/json"

    request = Request(
        url=url,
        data=payload,
        headers=headers,
        method=method.upper(),
    )

    try:

        with urlopen(
            request,
            timeout=timeout,
        ) as response:

            raw = (
                response
                .read()
                .decode(
                    "utf-8"
                )
            )

            try:

                data = (
                    json.loads(
                        raw
                    )
                    if raw
                    else {}
                )

            except json.JSONDecodeError:

                data = {
                    "raw":
                        raw,
                }

            return (
                response.status,
                data,
            )

    except HTTPError as error:

        raw = (
            error
            .read()
            .decode(
                "utf-8",
                errors="replace",
            )
        )

        try:

            data = (
                json.loads(
                    raw
                )
                if raw
                else {}
            )

        except json.JSONDecodeError:

            data = {
                "raw":
                    raw,
            }

        return (
            error.code,
            data,
        )

    except URLError as error:

        return (
            0,
            {
                "detail":
                    str(
                        error.reason
                    ),
            },
        )

    except Exception as error:

        return (
            0,
            {
                "detail":
                    str(
                        error
                    ),
            },
        )


# ================================================================
# STORE ISOLATION
# ================================================================

def build_workflow():

    return (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


def inspect_store_paths(
    workflow,
):

    ticket_store = (
        SOCTicketStore()
    )

    return {
        "active":
            normalize_path(
                ACTIVE_SOC_DATABASE_PATH
            ),

        "validation":
            normalize_path(
                VALIDATION_DATABASE_PATH
            ),

        "case":
            normalize_path(
                workflow
                .case_store
                .database_path
            ),

        "action":
            normalize_path(
                workflow
                .action_store
                .database_path
            ),

        "evidence":
            normalize_path(
                workflow
                .evidence_store
                .database_path
            ),

        "workflow_ticket":
            normalize_path(
                workflow
                .workflow
                .ticket_generator
                .store
                .database_path
            ),

        "ticket":
            normalize_path(
                ticket_store
                .database_path
            ),
    }


# ================================================================
# CONTROLLED RESPONSE-BRANCH FIXTURE
#
# This fixture does NOT represent detector truth.
#
# Phase 7A already validates the production conservative path.
#
# Phase 7B intentionally supplies a response recommendation only
# to exercise:
#
# Digital Twin
# -> response action
# -> PENDING approval
# -> analyst approval
# -> simulation-only routing
# -> persistence
# -> mitigation verification
#
# No real endpoint action is executed.
# ================================================================

def build_branch_intelligence(
    incident_id,
):

    token = (
        uuid.uuid4()
        .hex[
            :8
        ]
        .upper()
    )

    pid = (
        880000
        + int(
            token[
                :4
            ],
            16,
        )
        % 10000
    )

    device_id = (
        f"PHASE7B-DEVICE-{token}"
    )

    process = {
        "pid":
            pid,

        "name":
            "sentinelx_validation_process.exe",

        "exe":
            (
                r"C:\SentinelXValidation"
                r"\sentinelx_validation_process.exe"
            ),

        "behavior_score":
            92,

        "combined_threat_score":
            92,

        "threat_type":
            "PHASE7B_VALIDATION_ONLY",
    }

    evidence = {
        "processes": [
            process
        ],

        "files":
            [],

        "network_connections":
            [],

        "registry_artifacts":
            [],
    }

    intelligence = {
        "incident_id":
            incident_id,

        # --------------------------------------------------------
        # CONTROLLED BRANCH INPUT
        #
        # This is NOT replacing the production risk agent.
        # It is test input for response-workflow branch coverage.
        # --------------------------------------------------------

        "risk": {
            "risk_score":
                78,

            "risk_level":
                "HIGH",

            "requires_response":
                True,

            "requires_response_review":
                True,
        },

        "risk_score":
            78,

        "risk_level":
            "HIGH",

        # --------------------------------------------------------
        # CONTROLLED RESPONSE RECOMMENDATION
        # --------------------------------------------------------

        "response": {
            "response_level":
                "RESPONSE_REVIEW",

            "recommendation_count":
                1,

            "recommendations": [
                {
                    "action":
                        "PROCESS_TERMINATION_REVIEW",

                    "priority":
                        "HIGH",

                    "reason":
                        (
                            "Phase 7B validation-only "
                            "response branch."
                        ),

                    "requires_approval":
                        True,

                    "target":
                        process,
                }
            ],

            "execution_allowed":
                False,

            "simulation_only":
                True,
        },

        # --------------------------------------------------------
        # DIGITAL TWIN EVIDENCE
        # --------------------------------------------------------

        "coordinated_analysis": {
            "evidence":
                evidence,
        },

        "source_incident": {
            "incident_id":
                incident_id,

            "device_id":
                device_id,

            "hostname":
                "sentinelx-phase7b-host",

            "timeline":
                [],
        },

        "execution_enabled":
            False,

        "simulation_mode":
            True,
    }

    return (
        intelligence,
        evidence,
    )


# ================================================================
# SEED CONTROLLED CASE
#
# We intentionally call the real UnifiedSOCWorkflow under
# PersistentSOCWorkflow.
#
# This exercises:
#
# DigitalTwinDecisionIntegration
# DigitalTwinExplainability
# AutomaticTicketGenerator
# ResponseAction creation
# ApprovalWorkflow request
#
# The fixture bypasses the detector/risk-production path only
# because that path was already validated separately in Phase 7A.
# ================================================================

def seed_controlled_case(
    workflow,
):

    incident_id = (
        "PHASE7B-"
        + uuid.uuid4()
        .hex[
            :16
        ]
        .upper()
    )

    intelligence, evidence = (
        build_branch_intelligence(
            incident_id
        )
    )

    case_result = (
        workflow
        .workflow
        .create_case(
            incident_id=
                incident_id,

            intelligence=
                intelligence,
        )
    )

    persistence = (
        workflow.persist_case(
            case_result
        )
    )

    # ------------------------------------------------------------
    # Persist supporting evidence for full incident view.
    # ------------------------------------------------------------

    workflow.evidence_store.save_evidence_bundle(
        incident_id=
            incident_id,

        evidence=
            evidence,

        replace_existing=
            True,
    )

    workflow.evidence_store.save_timeline(
        incident_id=
            incident_id,

        timeline=
            [],

        replace_existing=
            True,
    )

    return (
        incident_id,
        intelligence,
        case_result,
        persistence,
    )


# ================================================================
# REPORT
# ================================================================

def save_report(
    results,
    incident_id,
):

    fields = [
        "scenario_id",
        "family",
        "scenario_name",
        "observed",
        "expected",
        "failure_layers",
        "passed",
        "notes",
    ]

    with CSV_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
        )

        writer.writeheader()

        writer.writerows(
            results
        )

    with JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            {
                "suite":
                    (
                        "SENTINEL-X PHASE 7B "
                        "APPROVAL AND SIMULATED RESPONSE"
                    ),

                "incident_id":
                    incident_id,

                "passed":
                    sum(
                        1
                        for row
                        in results
                        if row[
                            "passed"
                        ]
                    ),

                "failed":
                    sum(
                        1
                        for row
                        in results
                        if not row[
                            "passed"
                        ]
                    ),

                "results":
                    results,
            },
            handle,
            indent=2,
        )


def print_report(
    results,
    incident_id,
):

    print()

    print(
        "=" * 118
    )

    print(
        (
            "SENTINEL-X PHASE 7B — "
            "APPROVAL + SIMULATED RESPONSE VALIDATION"
        )
    )

    print(
        "=" * 118
    )

    print(
        "Incident ID:",
        incident_id
        or "NONE",
    )

    print(
        "-" * 118
    )

    for row in results:

        state = (
            "PASS"
            if row[
                "passed"
            ]
            else "FAIL"
        )

        print(
            f"{row['scenario_id']:<8} "
            f"{state:<5} "
            f"{row['scenario_name']:<63} "
            f"Observed={row['observed']}"
        )

    passed_count = sum(
        1
        for row
        in results
        if row[
            "passed"
        ]
    )

    print(
        "-" * 118
    )

    print(
        f"RESULT: "
        f"{passed_count}/{len(results)} PASS"
    )

    print(
        f"CSV   : {CSV_PATH}"
    )

    print(
        f"JSON  : {JSON_PATH}"
    )

    print(
        "=" * 118
    )


# ================================================================
# MAIN
# ================================================================

def main():

    results = []

    incident_id = ""

    # ============================================================
    # API HEALTH
    # ============================================================

    health_status, health = (
        api_request(
            "GET",
            "/api/v1/health",
        )
    )

    if health_status != 200:

        print(
            "ERROR: FastAPI is not reachable:",
            health,
        )

        return

    # ============================================================
    # WORKFLOW
    # ============================================================

    workflow = (
        build_workflow()
    )

    # ============================================================
    # 7B-01
    # STORE ISOLATION
    # ============================================================

    paths = (
        inspect_store_paths(
            workflow
        )
    )

    expected = (
        paths[
            "validation"
        ]
    )

    actual_store_paths = [
        paths[
            "case"
        ],
        paths[
            "action"
        ],
        paths[
            "evidence"
        ],
        paths[
            "workflow_ticket"
        ],
        paths[
            "ticket"
        ],
    ]

    isolation_passed = (
        IS_VALIDATION_MODE

        and

        paths[
            "active"
        ]
        == expected

        and

        all(
            path == expected
            for path
            in actual_store_paths
        )
    )

    add_result(
        results,

        "7B-01",

        "Validation SOC stores are isolated from live database",

        (
            f"active={paths['active'].name};"
            f"case={paths['case'].name};"
            f"action={paths['action'].name};"
            f"evidence={paths['evidence'].name};"
            f"workflow_ticket="
            f"{paths['workflow_ticket'].name};"
            f"ticket={paths['ticket'].name}"
        ),

        "all SOC stores -> sentinel_validation.db",

        isolation_passed,

        ""
        if isolation_passed
        else "VALIDATION_STORAGE_ISOLATION",
    )

    if not isolation_passed:

        save_report(
            results,
            incident_id,
        )

        print_report(
            results,
            incident_id,
        )

        print()

        print(
            "STOPPED: fix SOC database isolation "
            "before running response validation."
        )

        return

    # ============================================================
    # SEED CASE
    # ============================================================

    try:

        (
            incident_id,
            intelligence,
            seeded_case,
            persistence,
        ) = (
            seed_controlled_case(
                workflow
            )
        )

    except Exception as error:

        add_result(
            results,

            "7B-02",

            "Controlled Digital Twin branch fixture is created",

            (
                "error="
                + str(
                    error
                )
            ),

            "controlled simulation case created",

            False,

            "BRANCH_FIXTURE",
        )

        save_report(
            results,
            incident_id,
        )

        print_report(
            results,
            incident_id,
        )

        return

    # ============================================================
    # 7B-02
    # DIGITAL TWIN PLAN
    # ============================================================

    seeded_decision = safe_dict(
        seeded_case.get(
            "decision"
        )
    )

    seeded_best_plan = safe_dict(
        seeded_decision.get(
            "best_plan"
        )
    )

    seeded_actions = safe_list(
        seeded_case.get(
            "response_actions"
        )
    )

    b02_passed = (
        bool(
            seeded_best_plan
        )

        and

        seeded_decision.get(
            "requires_analyst_approval"
        )
        is True

        and

        len(
            seeded_actions
        )
        >= 1

        and

        seeded_case.get(
            "simulation_mode"
        )
        is True

        and

        seeded_case.get(
            "real_response_executed"
        )
        is False
    )

    add_result(
        results,

        "7B-02",

        "Digital Twin produces approval-required response plan",

        (
            f"plan="
            f"{seeded_best_plan.get('plan_name')};"
            f"actions={len(seeded_actions)};"
            f"approval="
            f"{seeded_decision.get('requires_analyst_approval')};"
            f"simulation="
            f"{seeded_case.get('simulation_mode')}"
        ),

        "plan exists with approval-required response action",

        b02_passed,

        ""
        if b02_passed
        else "DIGITAL_TWIN_BRANCH",
    )

    # ============================================================
    # 7B-03
    # API CASE PERSISTENCE
    # ============================================================

    case_status, api_case = (
        api_request(
            "GET",
            (
                "/api/v1/cases/"
                + incident_id
            ),
        )
    )

    api_ticket = safe_dict(
        api_case.get(
            "ticket"
        )
    )

    b03_passed = (
        case_status
        == 200

        and

        str(
            api_case.get(
                "incident_id"
            )
        )
        == incident_id

        and

        api_ticket.get(
            "approval_status"
        )
        == "PENDING"
    )

    add_result(
        results,

        "7B-03",

        "Controlled SOC case is visible through API",

        (
            f"http={case_status};"
            f"status={api_case.get('status')};"
            f"ticket={api_ticket.get('ticket_id')};"
            f"approval="
            f"{api_ticket.get('approval_status')}"
        ),

        "case visible with PENDING ticket",

        b03_passed,

        ""
        if b03_passed
        else "SOC_CASE_API",
    )

    # ============================================================
    # 7B-04
    # PENDING RESPONSE ACTION
    # ============================================================

    response_status, response_payload = (
        api_request(
            "GET",
            (
                "/api/v1/cases/"
                + incident_id
                + "/responses"
            ),
        )
    )

    pre_actions = safe_list(
        response_payload.get(
            "actions"
        )
    )

    pending = [
        action
        for action
        in pre_actions
        if (
            isinstance(
                action,
                dict,
            )

            and

            action.get(
                "approval_required"
            )
            is True

            and

            action.get(
                "approval_status"
            )
            == "PENDING"

            and

            action.get(
                "execution_status"
            )
            == "NOT_EXECUTED"
        )
    ]

    b04_passed = (
        response_status
        == 200

        and

        len(
            pre_actions
        )
        >= 1

        and

        len(
            pending
        )
        >= 1
    )

    add_result(
        results,

        "7B-04",

        "Response action begins in safe PENDING state",

        (
            f"http={response_status};"
            f"actions={len(pre_actions)};"
            f"pending={len(pending)}"
        ),

        "approval=PENDING and execution=NOT_EXECUTED",

        b04_passed,

        ""
        if b04_passed
        else "PENDING_ACTION_STATE",
    )

    # ============================================================
    # 7B-05
    # TICKET PERSISTENCE
    # ============================================================

    tickets_status, tickets_payload = (
        api_request(
            "GET",
            (
                "/api/v1/incidents/"
                + incident_id
                + "/tickets"
            ),
        )
    )

    tickets = safe_list(
        tickets_payload.get(
            "tickets"
        )
    )

    pending_tickets = [
        ticket
        for ticket
        in tickets
        if (
            isinstance(
                ticket,
                dict,
            )

            and

            str(
                ticket.get(
                    "approval_status"
                )
            ).upper()
            == "PENDING"
        )
    ]

    b05_passed = (
        tickets_status
        == 200

        and

        len(
            pending_tickets
        )
        >= 1
    )

    add_result(
        results,

        "7B-05",

        "SOC ticket persists with analyst approval pending",

        (
            f"http={tickets_status};"
            f"tickets={len(tickets)};"
            f"pending={len(pending_tickets)}"
        ),

        "ticket approval=PENDING",

        b05_passed,

        ""
        if b05_passed
        else "SOC_TICKET",
    )

    # ============================================================
    # 7B-06
    # ANALYST APPROVAL + SIMULATION
    # ============================================================

    approval_status, approval = (
        api_request(
            "POST",
            (
                "/api/v1/cases/"
                + incident_id
                + "/approve"
            ),
            {
                "analyst":
                    "phase7b-validation-analyst",

                "comment":
                    (
                        "Approved for Phase 7B "
                        "simulation-only validation."
                    ),
            },
        )
    )

    routing_results = safe_list(
        approval.get(
            "routing_results"
        )
    )

    safe_routes = [
        route
        for route
        in routing_results
        if (
            isinstance(
                route,
                dict,
            )

            and

            route.get(
                "success"
            )
            is True

            and

            str(
                route.get(
                    "status",
                    ""
                )
            ).upper()
            == "SIMULATED"

            and

            route.get(
                "simulation_mode"
            )
            is True

            and

            route.get(
                "executed"
            )
            is False
        )
    ]

    b06_passed = (
        approval_status
        == 200

        and

        approval.get(
            "success"
        )
        is True

        and

        str(
            approval.get(
                "status",
                ""
            )
        ).upper()
        == "SIMULATED_RESPONSE_COMPLETED"

        and

        approval.get(
            "simulation_mode"
        )
        is True

        and

        approval.get(
            "real_response_executed"
        )
        is False

        and

        len(
            safe_routes
        )
        == len(
            routing_results
        )

        and

        len(
            routing_results
        )
        >= 1
    )

    add_result(
        results,

        "7B-06",

        "Analyst approval routes actions through simulation only",

        (
            f"http={approval_status};"
            f"success={approval.get('success')};"
            f"status={approval.get('status')};"
            f"routes={len(routing_results)};"
            f"safe_routes={len(safe_routes)};"
            f"real_execution="
            f"{approval.get('real_response_executed')}"
        ),

        (
            "SIMULATED_RESPONSE_COMPLETED / "
            "executed=False"
        ),

        b06_passed,

        ""
        if b06_passed
        else "APPROVAL_SIMULATION",
    )

    # ============================================================
    # 7B-07
    # ACTION STATE PERSISTENCE
    # ============================================================

    post_response_status, post_response = (
        api_request(
            "GET",
            (
                "/api/v1/cases/"
                + incident_id
                + "/responses"
            ),
        )
    )

    post_actions = safe_list(
        post_response.get(
            "actions"
        )
    )

    successful_actions = [
        action
        for action
        in post_actions
        if (
            isinstance(
                action,
                dict,
            )

            and

            action.get(
                "approval_status"
            )
            == "APPROVED"

            and

            action.get(
                "execution_status"
            )
            == "SUCCESS"
        )
    ]

    b07_passed = (
        post_response_status
        == 200

        and

        len(
            post_actions
        )
        >= 1

        and

        len(
            successful_actions
        )
        == len(
            post_actions
        )
    )

    add_result(
        results,

        "7B-07",

        "Approved simulated action state persists",

        (
            f"http={post_response_status};"
            f"actions={len(post_actions)};"
            f"approved_success="
            f"{len(successful_actions)}"
        ),

        "all actions APPROVED + SUCCESS",

        b07_passed,

        ""
        if b07_passed
        else "ACTION_PERSISTENCE",
    )

    # ============================================================
    # 7B-08
    # TICKET STATE AFTER APPROVAL
    # ============================================================

    post_tickets_status, post_tickets_payload = (
        api_request(
            "GET",
            (
                "/api/v1/incidents/"
                + incident_id
                + "/tickets"
            ),
        )
    )

    post_tickets = safe_list(
        post_tickets_payload.get(
            "tickets"
        )
    )

    approved_tickets = [
        ticket
        for ticket
        in post_tickets
        if (
            isinstance(
                ticket,
                dict,
            )

            and

            str(
                ticket.get(
                    "approval_status"
                )
            ).upper()
            == "APPROVED"
        )
    ]

    b08_passed = (
        post_tickets_status
        == 200

        and

        len(
            approved_tickets
        )
        >= 1
    )

    add_result(
        results,

        "7B-08",

        "SOC ticket approval state persists",

        (
            f"http={post_tickets_status};"
            f"tickets={len(post_tickets)};"
            f"approved={len(approved_tickets)}"
        ),

        "ticket approval=APPROVED",

        b08_passed,

        ""
        if b08_passed
        else "TICKET_APPROVAL_PERSISTENCE",
    )

    # ============================================================
    # 7B-09
    # DOUBLE APPROVAL SAFETY
    # ============================================================

    duplicate_status, duplicate_result = (
        api_request(
            "POST",
            (
                "/api/v1/cases/"
                + incident_id
                + "/approve"
            ),
            {
                "analyst":
                    "phase7b-validation-analyst",

                "comment":
                    "Duplicate approval validation.",
            },
        )
    )

    b09_passed = (
        duplicate_status
        == 409
    )

    add_result(
        results,

        "7B-09",

        "Already-approved ticket cannot be approved again",

        (
            f"http={duplicate_status};"
            f"detail={duplicate_result.get('detail')}"
        ),

        "HTTP 409 on duplicate approval",

        b09_passed,

        ""
        if b09_passed
        else "APPROVAL_IDEMPOTENCY",
    )

    # ============================================================
    # 7B-10
    # MITIGATION + FULL INCIDENT VIEW
    # ============================================================

    verification_status, verification = (
        api_request(
            "POST",
            (
                "/api/v1/cases/"
                + incident_id
                + "/mitigation-verification"
            ),
            {
                "before_state": {
                    "risk_score":
                        78,

                    "suspicious_event_count":
                        8,

                    "active_indicator_count":
                        5,

                    "exposure_score":
                        80,
                },

                "simulated_after_state": {
                    "risk_score":
                        18,

                    "suspicious_event_count":
                        1,

                    "active_indicator_count":
                        1,

                    "exposure_score":
                        15,
                },

                "response_result":
                    approval,
            },
        )
    )

    full_status, full_incident = (
        api_request(
            "GET",
            (
                "/api/v1/incidents/"
                + incident_id
                + "/full"
            ),
        )
    )

    full_text = (
        json.dumps(
            full_incident,
            default=str,
        )
        .lower()
    )

    incident_visible = (
        incident_id.lower()
        in full_text
    )

    b10_passed = (
        verification_status
        == 200

        and

        verification.get(
            "success"
        )
        is True

        and

        str(
            verification.get(
                "status",
                ""
            )
        ).upper()
        == "SIMULATION_VERIFIED"

        and

        verification.get(
            "real_response_executed"
        )
        is False

        and

        full_status
        == 200

        and

        incident_visible
    )

    add_result(
        results,

        "7B-10",

        (
            "Simulated response reaches mitigation "
            "verification and full incident view"
        ),

        (
            f"verify_http={verification_status};"
            f"verify_status="
            f"{verification.get('status')};"
            f"full_http={full_status};"
            f"incident_visible={incident_visible};"
            f"real_execution="
            f"{verification.get('real_response_executed')}"
        ),

        (
            "SIMULATION_VERIFIED + complete "
            "persisted incident view"
        ),

        b10_passed,

        ""
        if b10_passed
        else "MITIGATION_FULL_INCIDENT",
    )

    # ============================================================
    # OUTPUT
    # ============================================================

    save_report(
        results,
        incident_id,
    )

    print_report(
        results,
        incident_id,
    )


# ================================================================
# ENTRY
# ================================================================

if __name__ == "__main__":

    main()