from __future__ import annotations

import csv
import json
import os
import time
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
    DATA_SOURCE_VALIDATION,
    IS_VALIDATION_MODE,
)

from detection.fusion.correlation_manager import (
    CorrelationManager,
)


# ================================================================
# CONFIGURATION
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
    / "soc_e2e_validation.csv"
)

JSON_PATH = (
    REPORT_DIR
    / "soc_e2e_validation.json"
)

API_BASE = (
    os.getenv(
        "SENTINEL_API_BASE_URL",
        "http://127.0.0.1:8003",
    )
    .rstrip("/")
)


# ================================================================
# BASIC HELPERS
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


def safe_float(
    value,
    default=0.0,
):

    try:
        return float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):
        return default


# ================================================================
# HTTP HELPER
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
# OPENAPI ROUTE HELPER
# ================================================================

def load_openapi():

    status, response = (
        api_request(
            "GET",
            "/openapi.json",
        )
    )

    if status != 200:

        return (
            status,
            {},
            {},
        )

    paths = safe_dict(
        response.get(
            "paths"
        )
    )

    return (
        status,
        response,
        paths,
    )


def route_exists(
    paths,
    path,
    method,
):

    operations = safe_dict(
        paths.get(
            path
        )
    )

    return (
        method.lower()
        in operations
    )


# ================================================================
# RESULT HELPER
# ================================================================

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
                "SOC_E2E",

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
# VALIDATION EVENT
#
# IMPORTANT:
#
# This is synthetic VALIDATION evidence.
#
# It must pass the CorrelationManager validation data-source gate,
# but it must NOT set:
#
#   synthetic=True
#   simulation_mode=True
#   detection_mode=SHADOW
#
# because the multi-agent evidence gate correctly treats those as
# non-authoritative incident evidence.
# ================================================================

def validation_event(
    *,
    event_id,
    event_type,
    timestamp,
    severity,
    category,
    device_id,
    scenario_id,
    run_id,
    process=None,
    file=None,
    network=None,
    registry=None,
    extra_metadata=None,
):

    metadata = {
        "data_source":
            DATA_SOURCE_VALIDATION,

        "synthetic_validation":
            True,

        "validation_mode":
            True,

        "sentinel_runtime_mode":
            "VALIDATION",

        "scenario_id":
            scenario_id,

        "validation_run_id":
            run_id,

        "event_category":
            category,

        "device_id":
            device_id,

        "authoritative_validation_evidence":
            True,
    }

    if isinstance(
        extra_metadata,
        dict,
    ):

        metadata.update(
            extra_metadata
        )

    metadata.pop(
        "synthetic",
        None,
    )

    metadata.pop(
        "simulation_mode",
        None,
    )

    return {
        "event_id":
            event_id,

        "event_type":
            event_type,

        "timestamp_unix":
            float(
                timestamp
            ),

        "timestamp":
            str(
                timestamp
            ),

        "source":
            "phase7_soc_e2e_validation",

        "severity":
            severity,

        "device_id":
            device_id,

        "hostname":
            "sentinelx-e2e-host",

        "event_category":
            category,

        "process":
            process
            or {},

        "file":
            file
            or {},

        "network":
            network
            or {},

        "registry":
            registry
            or {},

        "metadata":
            metadata,
    }


# ================================================================
# BUILD REPRESENTATIVE CROSS-TELEMETRY INCIDENT
# ================================================================

def build_e2e_events():

    run_token = (
        uuid.uuid4()
        .hex[
            :10
        ]
        .upper()
    )

    scenario_id = (
        f"PHASE7-E2E-{run_token}"
    )

    device_id = (
        f"sentinelx-e2e-device-{run_token}"
    )

    pid = (
        700000
        + (
            int(
                run_token[
                    :4
                ],
                16,
            )
            % 100000
        )
    )

    base_time = (
        time.time()
    )

    payload_name = (
        f"sentinelx_e2e_{run_token}.exe"
    )

    payload_path = (
        rf"C:\Users\Public\{payload_name}"
    )

    process_path = (
        r"C:\Windows\System32"
        r"\WindowsPowerShell\v1.0"
        r"\powershell.exe"
    )

    process = {
        "pid":
            pid,

        "name":
            "powershell.exe",

        "exe":
            process_path,

        "parent_name":
            "winword.exe",

        "parent_pid":
            pid - 1,

        # Inert validation metadata only.
        # This runner does not execute this command.
        "command_line":
            (
                "powershell.exe "
                "-WindowStyle Hidden "
                "-EncodedCommand "
                "SENTINEL_X_VALIDATION_ONLY"
            ),

        "create_time":
            base_time,

        "behavior_score":
            92,

        "combined_threat_score":
            92,

        "threat_type":
            "POWERSHELL_DOWNLOAD_EXECUTION",
    }

    events = [

        # ========================================================
        # PROCESS
        # ========================================================

        validation_event(
            event_id=
                f"{scenario_id}-PROCESS",

            event_type=
                "process_fusion_detection",

            timestamp=
                base_time,

            severity=
                "CRITICAL",

            category=
                "PROCESS",

            device_id=
                device_id,

            scenario_id=
                scenario_id,

            run_id=
                run_token,

            process=
                process,

            extra_metadata={
                "engine":
                    "process_threat_fusion_v3",

                "detected":
                    True,

                "threat_type":
                    "POWERSHELL_DOWNLOAD_EXECUTION",

                "detection_type":
                    "POWERSHELL_DOWNLOAD_EXECUTION",

                "risk_score":
                    92,

                "fusion_score":
                    92,

                "rule_score":
                    100,
            },
        ),

        # ========================================================
        # FILE
        # ========================================================

        validation_event(
            event_id=
                f"{scenario_id}-FILE",

            event_type=
                "file_create",

            timestamp=
                base_time + 5,

            severity=
                "HIGH",

            category=
                "FILE",

            device_id=
                device_id,

            scenario_id=
                scenario_id,

            run_id=
                run_token,

            process=
                process,

            file={
                "name":
                    payload_name,

                "path":
                    payload_path,

                "sha256":
                    (
                        "E2E"
                        + run_token
                        + "ABCDEF0123456789"
                    ),

                "action":
                    "CREATE",

                "static_risk_score":
                    70,
            },

            extra_metadata={
                "engine":
                    "file_behavior",

                "detected":
                    True,

                "threat_type":
                    "SUSPICIOUS_EXECUTABLE_CREATION",

                "detection_type":
                    "SUSPICIOUS_EXECUTABLE_CREATION",

                "risk_score":
                    72,
            },
        ),

        # ========================================================
        # NETWORK
        # ========================================================

        validation_event(
            event_id=
                f"{scenario_id}-NETWORK",

            event_type=
                "network_connect",

            timestamp=
                base_time + 10,

            severity=
                "HIGH",

            category=
                "NETWORK",

            device_id=
                device_id,

            scenario_id=
                scenario_id,

            run_id=
                run_token,

            network={
                "pid":
                    pid,

                "process_name":
                    "powershell.exe",

                "local_ip":
                    "10.10.10.25",

                "local_port":
                    53001,

                "remote_ip":
                    "198.51.100.200",

                "remote_port":
                    443,

                "protocol":
                    "TCP",

                "status":
                    "ESTABLISHED",
            },

            extra_metadata={
                "engine":
                    "network_behavior",

                "detected":
                    True,

                "threat_type":
                    "SUSPICIOUS_NETWORK_ACTIVITY",

                "detection_type":
                    "SUSPICIOUS_NETWORK_ACTIVITY",

                "risk_score":
                    80,
            },
        ),

        # ========================================================
        # REGISTRY
        # ========================================================

        validation_event(
            event_id=
                f"{scenario_id}-REGISTRY",

            event_type=
                "registry_modify",

            timestamp=
                base_time + 15,

            severity=
                "CRITICAL",

            category=
                "REGISTRY",

            device_id=
                device_id,

            scenario_id=
                scenario_id,

            run_id=
                run_token,

            registry={
                "pid":
                    pid,

                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "SentinelXE2EValidation",

                "value_data":
                    payload_path,

                "action":
                    "SET_VALUE",
            },

            extra_metadata={
                "engine":
                    "registry_behavior",

                "detected":
                    True,

                "threat_type":
                    "SUSPICIOUS_RUN_KEY_PERSISTENCE",

                "detection_type":
                    "SUSPICIOUS_RUN_KEY_PERSISTENCE",

                "risk_score":
                    88,
            },
        ),
    ]

    return {
        "run_token":
            run_token,

        "scenario_id":
            scenario_id,

        "device_id":
            device_id,

        "pid":
            pid,

        "events":
            events,
    }


# ================================================================
# SEED THROUGH REAL CORRELATION MANAGER
# ================================================================

def seed_detected_incident():

    if not IS_VALIDATION_MODE:

        raise RuntimeError(
            "Phase-7 runner requires "
            "SENTINEL_RUNTIME_MODE=VALIDATION."
        )

    fixture = (
        build_e2e_events()
    )

    manager = (
        CorrelationManager(
            correlation_window_seconds=
                120,

            incident_threshold=
                35,
        )
    )

    final_incident = None

    correlation_results = []

    for item in fixture[
        "events"
    ]:

        result = (
            manager.process_event(
                item
            )
        )

        correlation_results.append(
            result
        )

        candidate = (
            result.get(
                "incident"
            )
        )

        if isinstance(
            candidate,
            dict,
        ):

            final_incident = (
                candidate
            )

    if (
        final_incident is None
        and len(
            manager.incidents
        )
        == 1
    ):

        final_incident = next(
            iter(
                manager.incidents.values()
            )
        )

    fixture[
        "correlation_results"
    ] = correlation_results

    fixture[
        "incident"
    ] = (
        final_incident
        or {}
    )

    return fixture


# ================================================================
# SAVE REPORT
# ================================================================

def save_reports(
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

        writer = (
            csv.DictWriter(
                handle,
                fieldnames=fields,
            )
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
                        "SENTINEL-X PHASE 7 "
                        "SOC E2E VALIDATION"
                    ),

                "api_base":
                    API_BASE,

                "incident_id":
                    incident_id,

                "validation_mode":
                    bool(
                        IS_VALIDATION_MODE
                    ),

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


# ================================================================
# PRINT REPORT
# ================================================================

def print_results(
    results,
    incident_id,
):

    print()

    print(
        "=" * 118
    )

    print(
        (
            "SENTINEL-X PHASE 7 — "
            "COMPLETE SOC END-TO-END VALIDATION"
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
            f"{row['scenario_name']:<65} "
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

        print()

        print(
            "ERROR: SENTINEL-X API is not reachable."
        )

        print(
            f"API: {API_BASE}"
        )

        print(
            "Response:",
            health,
        )

        return

    # ============================================================
    # OPENAPI / ROUTE DISCOVERY
    # ============================================================

    openapi_status, openapi, paths = (
        load_openapi()
    )

    print()

    print(
        "OpenAPI status:",
        openapi_status,
    )

    important_routes = {
        "approve":
            (
                "/api/v1/cases/{incident_id}/approve",
                "post",
            ),

        "reject":
            (
                "/api/v1/cases/{incident_id}/reject",
                "post",
            ),

        "timeline":
            (
                "/api/v1/cases/{incident_id}/timeline",
                "get",
            ),

        "incident_tickets":
            (
                "/api/v1/incidents/{incident_id}/tickets",
                "get",
            ),

        "full_incident":
            (
                "/api/v1/incidents/{incident_id}/full",
                "get",
            ),
    }

    for name, (
        path,
        method,
    ) in important_routes.items():

        print(
            f"Route {name:<18}:",
            (
                "AVAILABLE"
                if route_exists(
                    paths,
                    path,
                    method,
                )
                else "MISSING"
            ),
        )

    # ============================================================
    # BUILD INCIDENT
    # ============================================================

    fixture = (
        seed_detected_incident()
    )

    incident = safe_dict(
        fixture.get(
            "incident"
        )
    )

    incident_id = str(
        incident.get(
            "incident_id"
        )
        or ""
    )

    categories = {
        str(
            category
        ).upper()
        for category
        in safe_list(
            incident.get(
                "categories"
            )
        )
    }

    incident_event_count = (
        incident.get(
            "event_count"
        )
    )

    if incident_event_count is None:

        incident_event_count = len(
            safe_list(
                incident.get(
                    "event_ids"
                )
            )
        )

    # ============================================================
    # E2E-01
    # CORRELATION
    # ============================================================

    e2e01_passed = (
        bool(
            incident_id
        )

        and

        incident_event_count
        == 4

        and

        {
            "PROCESS",
            "FILE",
            "NETWORK",
            "REGISTRY",
        }.issubset(
            categories
        )

        and

        safe_float(
            incident.get(
                "correlation_score"
            )
        )
        >= 80
    )

    add_result(
        results,

        "E2E-01",

        (
            "Authoritative validation detections "
            "correlate into one incident"
        ),

        (
            f"id={incident_id or 'NONE'};"
            f"score={incident.get('correlation_score')};"
            f"events={incident_event_count};"
            f"categories="
            f"{','.join(sorted(categories))}"
        ),

        (
            "one incident / score>=80 / "
            "4 cross-telemetry events"
        ),

        e2e01_passed,

        ""
        if e2e01_passed
        else "CORRELATION_INCIDENT",
    )

    # ============================================================
    # E2E-02
    # DETECTED INCIDENT API
    # ============================================================

    detected_status = 0
    detected = {}

    if incident_id:

        detected_status, detected = (
            api_request(
                "GET",
                (
                    "/api/v1/detected-incidents/"
                    + incident_id
                ),
            )
        )

    e2e02_passed = (
        detected_status
        == 200

        and

        str(
            detected.get(
                "incident_id"
            )
        )
        == incident_id
    )

    add_result(
        results,

        "E2E-02",

        (
            "Detected incident persists "
            "and reloads through API"
        ),

        (
            f"http={detected_status};"
            f"id={detected.get('incident_id')};"
            f"events={detected.get('event_count')};"
            f"score={detected.get('correlation_score')}"
        ),

        "HTTP 200 and matching incident",

        e2e02_passed,

        ""
        if e2e02_passed
        else "DETECTED_INCIDENT_API",
    )

    # ============================================================
    # E2E-03
    # MULTI-AGENT INVESTIGATION
    # ============================================================

    investigate_status = 0
    investigate = {}

    if incident_id:

        investigate_status, investigate = (
            api_request(
                "POST",
                (
                    "/api/v1/detected-incidents/"
                    + incident_id
                    + "/investigate"
                ),
            )
        )

    multi_agent = safe_dict(
        investigate.get(
            "multi_agent"
        )
    )

    already_in_soc = (
        investigate.get(
            "already_in_soc"
        )
        is True
    )

    agent_status = str(
        multi_agent.get(
            "status",
            ""
        )
    ).upper()

    e2e03_passed = (
        investigate_status
        == 200

        and

        investigate.get(
            "success"
        )
        is True

        and

        (
            already_in_soc

            or

            agent_status
            == "COMPLETED"
        )
    )

    add_result(
        results,

        "E2E-03",

        (
            "Detected incident completes "
            "AI multi-agent investigation"
        ),

        (
            f"http={investigate_status};"
            f"success={investigate.get('success')};"
            f"already_in_soc={already_in_soc};"
            f"agent_status={agent_status};"
            f"case_status={investigate.get('status')}"
        ),

        (
            "investigation success / "
            "multi-agent COMPLETED"
        ),

        e2e03_passed,

        ""
        if e2e03_passed
        else "MULTI_AGENT_INVESTIGATION",

        (
            ""
            if e2e03_passed
            else json.dumps(
                investigate,
                default=str,
            )[
                :1200
            ]
        ),
    )

    # ============================================================
    # E2E-04
    # CASE + TICKET PERSISTENCE
    # ============================================================

    case_status = 0
    case = {}

    if incident_id:

        case_status, case = (
            api_request(
                "GET",
                (
                    "/api/v1/cases/"
                    + incident_id
                ),
            )
        )

    ticket = safe_dict(
        case.get(
            "ticket"
        )
    )

    e2e04_passed = (
        case_status
        == 200

        and

        str(
            case.get(
                "incident_id"
            )
        )
        == incident_id

        and

        bool(
            ticket.get(
                "ticket_id"
            )
        )

        and

        case.get(
            "simulation_mode"
        )
        is True

        and

        case.get(
            "real_response_executed"
        )
        is False
    )

    add_result(
        results,

        "E2E-04",

        (
            "Persistent SOC case "
            "and ticket reload correctly"
        ),

        (
            f"http={case_status};"
            f"status={case.get('status')};"
            f"ticket={ticket.get('ticket_id')};"
            f"actions={case.get('response_action_count')}"
        ),

        (
            "persistent case + ticket + "
            "simulation safety"
        ),

        e2e04_passed,

        ""
        if e2e04_passed
        else "SOC_CASE_PERSISTENCE",
    )

    # ============================================================
    # E2E-05
    # RISK ASSESSMENT
    # ============================================================

    risk_score = (
        multi_agent.get(
            "risk_score"
        )
    )

    risk_level = (
        multi_agent.get(
            "risk_level"
        )
    )

    if risk_score is None:

        decision_for_risk = safe_dict(
            case.get(
                "decision"
            )
        )

        risk_score = (
            decision_for_risk.get(
                "initial_risk_score"
            )
        )

        risk_level = (
            decision_for_risk.get(
                "initial_risk_level"
            )
        )

    numeric_risk = safe_float(
        risk_score
    )

    e2e05_passed = (
        numeric_risk
        > 0

        and

        str(
            risk_level
            or ""
        ).upper()
        in {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }
    )

    add_result(
        results,

        "E2E-05",

        (
            "Risk assessment is produced "
            "from persisted evidence"
        ),

        (
            f"risk_score={risk_score};"
            f"risk_level={risk_level}"
        ),

        "risk_score > 0 with valid risk level",

        e2e05_passed,

        ""
        if e2e05_passed
        else "RISK_ASSESSMENT",
    )

    # ============================================================
    # E2E-06
    # DIGITAL TWIN
    #
    # Current conservative risk policy may correctly produce
    # NO_RESPONSE_PLAN_AVAILABLE for low/unverified risk.
    # ============================================================

    twin_status = 0
    twin = {}

    if incident_id:

        twin_status, twin = (
            api_request(
                "GET",
                (
                    "/api/v1/cases/"
                    + incident_id
                    + "/digital-twin"
                ),
            )
        )

    decision = safe_dict(
        twin.get(
            "decision"
        )
    )

    best_plan = safe_dict(
        decision.get(
            "best_plan"
        )
    )

    ranked_plans = safe_list(
        decision.get(
            "ranked_plans"
        )
    )

    decision_code = str(
        decision.get(
            "decision",
            "",
        )
    ).upper()

    try:

        candidate_action_count = int(
            decision.get(
                "candidate_action_count",
                0,
            )
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):

        candidate_action_count = 0

    safe_no_response_plan = (
        numeric_risk
        < 35

        and

        candidate_action_count
        == 0

        and

        not best_plan

        and

        len(
            ranked_plans
        )
        == 0

        and

        decision_code
        == "NO_RESPONSE_PLAN_AVAILABLE"
    )

    response_plan_created = (
        bool(
            best_plan
        )

        or

        len(
            ranked_plans
        )
        > 0
    )

    e2e06_passed = (
        twin_status
        == 200

        and

        bool(
            decision
        )

        and

        twin.get(
            "simulation_mode"
        )
        is True

        and

        twin.get(
            "real_endpoint_modified"
        )
        is False

        and

        (
            safe_no_response_plan

            or

            response_plan_created
        )
    )

    add_result(
        results,

        "E2E-06",

        (
            "Digital Twin follows "
            "conservative response policy"
        ),

        (
            f"http={twin_status};"
            f"risk={decision.get('initial_risk_score')};"
            f"level={decision.get('initial_risk_level')};"
            f"candidate_actions={candidate_action_count};"
            f"decision={decision_code};"
            f"best_plan="
            f"{best_plan.get('plan_name') or best_plan.get('plan_id')};"
            f"simulation={twin.get('simulation_mode')}"
        ),

        (
            "low/unverified risk => safe no-response plan; "
            "otherwise valid Digital Twin plan"
        ),

        e2e06_passed,

        ""
        if e2e06_passed
        else "DIGITAL_TWIN",
    )

    # ============================================================
    # E2E-07
    # RESPONSE / APPROVAL GATE
    # ============================================================

    responses_status = 0
    responses = {}

    if incident_id:

        responses_status, responses = (
            api_request(
                "GET",
                (
                    "/api/v1/cases/"
                    + incident_id
                    + "/responses"
                ),
            )
        )

    actions = safe_list(
        responses.get(
            "actions"
        )
    )

    pending_actions = [
        action
        for action
        in actions
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

            str(
                action.get(
                    "approval_status",
                    ""
                )
            ).upper()
            == "PENDING"
        )
    ]

    ticket_approval_status = str(
        ticket.get(
            "approval_status",
            "",
        )
    ).upper()

    safe_no_approval_required = (
        numeric_risk
        < 35

        and

        len(
            pending_actions
        )
        == 0

        and

        ticket_approval_status
        in {
            "",
            "NOT_REQUIRED",
        }

        and

        decision_code
        == "NO_RESPONSE_PLAN_AVAILABLE"
    )

    approval_required_branch = (
        len(
            actions
        )
        >= 1

        and

        len(
            pending_actions
        )
        >= 1
    )

    e2e07_passed = (
        responses_status
        == 200

        and

        responses.get(
            "simulation_mode"
        )
        is True

        and

        responses.get(
            "real_response_executed"
        )
        is False

        and

        (
            safe_no_approval_required

            or

            approval_required_branch
        )
    )

    add_result(
        results,

        "E2E-07",

        (
            "Response policy correctly "
            "controls analyst approval"
        ),

        (
            f"http={responses_status};"
            f"actions={len(actions)};"
            f"pending={len(pending_actions)};"
            f"ticket_approval="
            f"{ticket_approval_status};"
            f"decision={decision_code}"
        ),

        (
            "safe low-risk case => NOT_REQUIRED; "
            "response case => PENDING analyst approval"
        ),

        e2e07_passed,

        ""
        if e2e07_passed
        else "APPROVAL_GATE",
    )

    # ============================================================
    # E2E-08
    # APPROVAL CONTRACT
    #
    # If a pending action exists:
    #   actually run the approval route.
    #
    # If no response is required:
    #   DO NOT force approval.
    #   Verify that the approval API exists.
    # ============================================================

    approve_status = None
    approval = {}

    approval_route_exists = (
        route_exists(
            paths,
            (
                "/api/v1/cases/"
                "{incident_id}/approve"
            ),
            "post",
        )
    )

    if pending_actions:

        approve_status, approval = (
            api_request(
                "POST",
                (
                    "/api/v1/cases/"
                    + incident_id
                    + "/approve"
                ),
                {
                    "analyst":
                        "phase7-validation-analyst",

                    "comment":
                        (
                            "Phase-7 E2E validation. "
                            "Simulation only."
                        ),
                },
            )
        )

        e2e08_passed = (
            approve_status
            == 200

            and

            approval.get(
                "success"
            )
            is True

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

            str(
                approval.get(
                    "status",
                    ""
                )
            ).upper()
            == "SIMULATED_RESPONSE_COMPLETED"
        )

        observed_e2e08 = (
            f"http={approve_status};"
            f"route_exists={approval_route_exists};"
            f"success={approval.get('success')};"
            f"status={approval.get('status')};"
            f"real_execution="
            f"{approval.get('real_response_executed')}"
        )

        expected_e2e08 = (
            "PENDING approval -> "
            "SIMULATED_RESPONSE_COMPLETED"
        )

    else:

        e2e08_passed = (
            openapi_status
            == 200

            and

            approval_route_exists

            and

            ticket_approval_status
            in {
                "",
                "NOT_REQUIRED",
            }

            and

            len(
                pending_actions
            )
            == 0
        )

        observed_e2e08 = (
            "approval_not_required=True;"
            f"route_exists={approval_route_exists};"
            f"ticket_approval={ticket_approval_status};"
            f"actions={len(actions)};"
            f"pending={len(pending_actions)}"
        )

        expected_e2e08 = (
            "no forced approval for low-risk case; "
            "approval API remains registered"
        )

    add_result(
        results,

        "E2E-08",

        (
            "Approval contract respects "
            "current response policy"
        ),

        observed_e2e08,

        expected_e2e08,

        e2e08_passed,

        ""
        if e2e08_passed
        else "APPROVAL_RESPONSE_ROUTING",

        (
            ""
            if e2e08_passed
            else json.dumps(
                approval,
                default=str,
            )[
                :1200
            ]
        ),
    )

    # ============================================================
    # E2E-09
    # SIMULATED MITIGATION VERIFICATION
    # ============================================================

    before_state = {
        "risk_score":
            85,

        "suspicious_event_count":
            12,

        "active_indicator_count":
            8,

        "exposure_score":
            90,
    }

    simulated_after_state = {
        "risk_score":
            20,

        "suspicious_event_count":
            2,

        "active_indicator_count":
            1,

        "exposure_score":
            20,
    }

    response_result = (
        dict(
            approval
        )
        if isinstance(
            approval,
            dict,
        )
        else {}
    )

    if not response_result:

        response_result = {
            "status":
                "NO_RESPONSE_REQUIRED",

            "decision":
                decision_code,
        }

    response_result[
        "simulation_mode"
    ] = True

    response_result[
        "real_response_executed"
    ] = False

    verification_status = 0
    verification = {}

    if incident_id:

        verification_status, verification = (
            api_request(
                "POST",
                (
                    "/api/v1/cases/"
                    + incident_id
                    + "/mitigation-verification"
                ),
                {
                    "before_state":
                        before_state,

                    "simulated_after_state":
                        simulated_after_state,

                    "response_result":
                        response_result,
                },
            )
        )

    persisted_status = 0
    persisted_verification = {}

    if incident_id:

        persisted_status, persisted_verification = (
            api_request(
                "GET",
                (
                    "/api/v1/cases/"
                    + incident_id
                    + "/mitigation-verification"
                ),
            )
        )

    e2e09_passed = (
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
            "persisted"
        )
        is True

        and

        persisted_status
        == 200

        and

        persisted_verification.get(
            "verified"
        )
        is True

        and

        persisted_verification.get(
            "real_response_executed"
        )
        is False
    )

    add_result(
        results,

        "E2E-09",

        (
            "Simulated mitigation "
            "is verified and persisted"
        ),

        (
            f"post_http={verification_status};"
            f"status={verification.get('status')};"
            f"persisted={verification.get('persisted')};"
            f"get_http={persisted_status};"
            f"verified="
            f"{persisted_verification.get('verified')}"
        ),

        "SIMULATION_VERIFIED and persisted",

        e2e09_passed,

        ""
        if e2e09_passed
        else "MITIGATION_VERIFICATION",
    )

    # ============================================================
    # E2E-10
    # FRONTEND / COMPLETE API CONTRACT
    # ============================================================

    full_route_exists = (
        route_exists(
            paths,
            (
                "/api/v1/incidents/"
                "{incident_id}/full"
            ),
            "get",
        )
    )

    tickets_route_exists = (
        route_exists(
            paths,
            (
                "/api/v1/incidents/"
                "{incident_id}/tickets"
            ),
            "get",
        )
    )

    full_status = 0
    full_incident = {}

    tickets_status = 0
    incident_tickets = {}

    dashboard_status = 0
    dashboard = {}

    if incident_id:

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

        tickets_status, incident_tickets = (
            api_request(
                "GET",
                (
                    "/api/v1/incidents/"
                    + incident_id
                    + "/tickets"
                ),
            )
        )

    dashboard_status, dashboard = (
        api_request(
            "GET",
            "/api/v1/dashboard/summary",
        )
    )

    full_text = (
        json.dumps(
            full_incident,
            default=str,
        )
        .lower()
    )

    full_has_incident = (
        incident_id.lower()
        in full_text
        if incident_id
        else False
    )

    try:

        ticket_count = int(
            incident_tickets.get(
                "count",
                0,
            )
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):

        ticket_count = 0

    e2e10_passed = (
        full_route_exists

        and

        tickets_route_exists

        and

        full_status
        == 200

        and

        full_has_incident

        and

        dashboard_status
        == 200

        and

        isinstance(
            dashboard,
            dict,
        )

        and

        len(
            dashboard
        )
        > 0

        and

        tickets_status
        == 200

        and

        ticket_count
        >= 1
    )

    add_result(
        results,

        "E2E-10",

        (
            "Threat/SOC frontend API contract "
            "exposes complete incident state"
        ),

        (
            f"full_route={full_route_exists};"
            f"tickets_route={tickets_route_exists};"
            f"full_http={full_status};"
            f"dashboard_http={dashboard_status};"
            f"tickets_http={tickets_status};"
            f"ticket_count={ticket_count};"
            f"incident_visible={full_has_incident}"
        ),

        (
            "full incident + dashboard + ticket APIs "
            "all expose persisted workflow"
        ),

        e2e10_passed,

        ""
        if e2e10_passed
        else "API_FRONTEND_DATA_CONTRACT",
    )

    # ============================================================
    # REPORT
    # ============================================================

    save_reports(
        results,
        incident_id,
    )

    print_results(
        results,
        incident_id,
    )


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()