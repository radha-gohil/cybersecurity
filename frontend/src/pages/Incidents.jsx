import {
    useEffect,
    useMemo,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";

import {
    getDetectedIncidents,
    getSOCCases,
    investigateDetectedIncident,
} from "../api/sentinelApi";


// ================================================================
// NORMALIZATION HELPERS
// ================================================================

function normalizeDetectedIncident(
    incident
) {

    const eventIds =
        Array.isArray(
            incident?.event_ids
        )
            ? incident.event_ids
            : [];


    return {

        incident_id:
            incident?.incident_id,

        title:
            incident?.title
            || incident?.incident_id
            || "Unknown incident",

        source:
            incident?.soc_case_exists
                ? "DETECTION + SOC"
                : "DETECTION",

        correlation_score:
            incident?.correlation_score
            ?? null,

        risk_score:
            incident?.risk_score
            ?? null,

        risk_level:
            incident?.risk_level
            || incident?.severity
            || "UNKNOWN",

        severity:
            incident?.severity
            || incident?.risk_level
            || "UNKNOWN",

        event_count:
            incident?.event_count
            ?? eventIds.length
            ?? 0,

        soc_case_exists:
            Boolean(
                incident?.soc_case_exists
            ),

        soc_case_status:
            incident?.soc_case_status
            || null,

        case_status:
            incident?.soc_case_status
            || null,

        approval_status:
            incident?.approval_status
            || null,

        ticket_id:
            incident?.ticket_id
            || null,

        ticket_priority:
            incident?.ticket_priority
            || null,

        selected_plan:
            incident?.selected_plan
            || null,

        residual_risk:
            incident?.residual_risk
            ?? incident?.predicted_residual_risk
            ?? null,

        mitigation_status:
            incident?.mitigation_status
            || "NOT_VERIFIED",

        created_at:
            incident?.created_at
            || incident?.updated_at
            || null,

        raw_detected_incident:
            incident,
    };
}


function normalizeSOCCase(
    socCase
) {

    const ticketData =
        socCase?.ticket_data
        || socCase?.ticket
        || {};


    const decision =
        socCase?.decision
        || socCase?.digital_twin_decision
        || {};


    const intelligence =
        socCase?.intelligence
        || {};


    const mitigation =
        socCase?.mitigation_verification
        || {};


    return {

        incident_id:
            socCase?.incident_id,

        title:
            socCase?.title
            || intelligence?.title
            || socCase?.incident_id
            || "Unknown incident",

        source:
            "SOC",

        correlation_score:
            socCase?.correlation_score
            ?? intelligence?.correlation_score
            ?? null,

        risk_score:
            socCase?.risk_score
            ?? intelligence?.risk_score
            ?? null,

        risk_level:
            socCase?.risk_level
            || socCase?.severity
            || intelligence?.risk_level
            || intelligence?.severity
            || "UNKNOWN",

        severity:
            socCase?.severity
            || socCase?.risk_level
            || intelligence?.severity
            || intelligence?.risk_level
            || "UNKNOWN",

        event_count:
            socCase?.event_count
            ?? intelligence?.event_count
            ?? 0,

        soc_case_exists:
            true,

        soc_case_status:
            socCase?.case_status
            || socCase?.status
            || null,

        case_status:
            socCase?.case_status
            || socCase?.status
            || null,

        approval_status:
            socCase?.approval_status
            || ticketData?.approval_status
            || null,

        ticket_id:
            socCase?.ticket_id
            || ticketData?.ticket_id
            || null,

        ticket_priority:
            socCase?.ticket_priority
            || ticketData?.priority
            || null,

        selected_plan:
            socCase?.selected_plan
            || decision?.selected_plan_name
            || decision?.selected_plan
            || decision?.plan_name
            || null,

        residual_risk:
            socCase?.residual_risk
            ?? socCase?.predicted_residual_risk
            ?? decision?.predicted_residual_risk
            ?? decision?.residual_risk
            ?? null,

        mitigation_status:
            socCase?.mitigation_status
            || mitigation?.status
            || "NOT_VERIFIED",

        created_at:
            socCase?.created_at
            || socCase?.updated_at
            || null,

        raw_soc_case:
            socCase,
    };
}


function mergeIncidentSources(
    detectedIncidents,
    socCases
) {

    const incidentMap =
        new Map();


    detectedIncidents.forEach(
        (incident) => {

            const normalized =
                normalizeDetectedIncident(
                    incident
                );


            if (
                normalized.incident_id
            ) {

                incidentMap.set(
                    normalized.incident_id,
                    normalized
                );
            }
        }
    );


    socCases.forEach(
        (socCase) => {

            const normalized =
                normalizeSOCCase(
                    socCase
                );


            if (
                !normalized.incident_id
            ) {
                return;
            }


            const existing =
                incidentMap.get(
                    normalized.incident_id
                );


            if (!existing) {

                incidentMap.set(
                    normalized.incident_id,
                    normalized
                );

                return;
            }


            incidentMap.set(
                normalized.incident_id,
                {
                    ...existing,

                    source:
                        "DETECTION + SOC",

                    title:
                        normalized.title
                        || existing.title,

                    correlation_score:
                        normalized.correlation_score
                        ?? existing.correlation_score,

                    risk_score:
                        normalized.risk_score
                        ?? existing.risk_score,

                    risk_level:
                        normalized.risk_level !== "UNKNOWN"
                            ? normalized.risk_level
                            : existing.risk_level,

                    severity:
                        normalized.severity !== "UNKNOWN"
                            ? normalized.severity
                            : existing.severity,

                    event_count:
                        normalized.event_count
                        || existing.event_count,

                    soc_case_exists:
                        true,

                    soc_case_status:
                        normalized.soc_case_status
                        || existing.soc_case_status,

                    case_status:
                        normalized.case_status
                        || existing.case_status,

                    approval_status:
                        normalized.approval_status
                        || existing.approval_status,

                    ticket_id:
                        normalized.ticket_id
                        || existing.ticket_id,

                    ticket_priority:
                        normalized.ticket_priority
                        || existing.ticket_priority,

                    selected_plan:
                        normalized.selected_plan
                        || existing.selected_plan,

                    residual_risk:
                        normalized.residual_risk
                        ?? existing.residual_risk,

                    mitigation_status:
                        normalized.mitigation_status !== "NOT_VERIFIED"
                            ? normalized.mitigation_status
                            : existing.mitigation_status,

                    created_at:
                        existing.created_at
                        || normalized.created_at,

                    raw_soc_case:
                        socCase,
                }
            );
        }
    );


    return Array.from(
        incidentMap.values()
    ).sort(
        (
            first,
            second
        ) => {

            const firstTime =
                first.created_at
                    ? new Date(
                        first.created_at
                    ).getTime()
                    : 0;


            const secondTime =
                second.created_at
                    ? new Date(
                        second.created_at
                    ).getTime()
                    : 0;


            return secondTime - firstTime;
        }
    );
}


// ================================================================
// COMPONENT
// ================================================================

function Incidents() {

    const navigate =
        useNavigate();


    const [
        incidents,
        setIncidents,
    ] = useState([]);


    const [
        loading,
        setLoading,
    ] = useState(true);


    const [
        error,
        setError,
    ] = useState("");


    const [
        investigatingId,
        setInvestigatingId,
    ] = useState("");


    const [
        riskLevel,
        setRiskLevel,
    ] = useState("");


    const [
        status,
        setStatus,
    ] = useState("");


    const [
        minRisk,
        setMinRisk,
    ] = useState("");


    // ============================================================
    // LOAD BOTH INCIDENT SOURCES
    // ============================================================

    const loadIncidents =
        async () => {

            try {

                setLoading(
                    true
                );

                setError(
                    ""
                );


                const [
                    detectedResult,
                    socResult,
                ] =
                    await Promise.all([
                        getDetectedIncidents(
                            1000
                        ),

                        getSOCCases(
                            1000
                        ),
                    ]);


                const detectedIncidents =
                    Array.isArray(
                        detectedResult?.incidents
                    )
                        ? detectedResult.incidents
                        : [];


                const socCases =
                    Array.isArray(
                        socResult?.cases
                    )
                        ? socResult.cases
                        : [];


                const merged =
                    mergeIncidentSources(
                        detectedIncidents,
                        socCases
                    );


                setIncidents(
                    merged
                );


            } catch (err) {

                console.error(
                    "Incident loading failed:",
                    err
                );


                setError(
                    err?.message
                    || "Unable to load incidents."
                );


            } finally {

                setLoading(
                    false
                );
            }
        };


    useEffect(
        () => {

            loadIncidents();

        },
        []
    );


    // ============================================================
    // FILTERING
    // ============================================================

    const filteredIncidents =
        useMemo(
            () => {

                return incidents.filter(
                    (incident) => {

                        if (riskLevel) {

                            const currentRisk =
                                String(
                                    incident.risk_level
                                    || incident.severity
                                    || ""
                                ).toUpperCase();


                            if (
                                currentRisk !==
                                riskLevel.toUpperCase()
                            ) {

                                return false;
                            }
                        }


                        if (status) {

                            if (
                                status ===
                                "DETECTED_ONLY"
                            ) {

                                if (
                                    incident.soc_case_exists
                                ) {

                                    return false;
                                }

                            } else {

                                const currentStatus =
                                    String(
                                        incident.soc_case_status
                                        || incident.case_status
                                        || ""
                                    ).toUpperCase();


                                if (
                                    currentStatus !==
                                    status.toUpperCase()
                                ) {

                                    return false;
                                }
                            }
                        }


                        if (
                            minRisk !== ""
                        ) {

                            const minimum =
                                Number(
                                    minRisk
                                );


                            const currentRiskScore =
                                Number(
                                    incident.risk_score
                                );


                            if (
                                !Number.isFinite(
                                    currentRiskScore
                                )
                                || currentRiskScore
                                    < minimum
                            ) {

                                return false;
                            }
                        }


                        return true;
                    }
                );
            },
            [
                incidents,
                riskLevel,
                status,
                minRisk,
            ]
        );


    const clearFilters =
        () => {

            setRiskLevel(
                ""
            );

            setStatus(
                ""
            );

            setMinRisk(
                ""
            );
        };


    // ============================================================
    // DISPLAY HELPERS
    // ============================================================

    const getRiskClass =
        (
            risk
        ) => {

            const value =
                String(
                    risk || ""
                ).toUpperCase();


            if (
                value === "CRITICAL"
            ) {

                return "badge critical";
            }


            if (
                value === "HIGH"
            ) {

                return "badge high";
            }


            if (
                value === "MEDIUM"
            ) {

                return "badge medium";
            }


            if (
                value === "LOW"
            ) {

                return "badge low";
            }


            return "badge neutral";
        };


    const formatDate =
        (
            value
        ) => {

            if (!value) {

                return "-";
            }


            const date =
                new Date(
                    value
                );


            if (
                Number.isNaN(
                    date.getTime()
                )
            ) {

                return value;
            }


            return date.toLocaleString();
        };


    const formatCorrelation =
        (
            value
        ) => {

            if (
                value === null
                || value === undefined
                || value === ""
            ) {

                return "-";
            }


            const number =
                Number(
                    value
                );


            if (
                !Number.isFinite(
                    number
                )
            ) {

                return String(
                    value
                );
            }


            return number.toFixed(
                3
            );
        };


    const formatStatus =
        (
            value,
            fallback = "-"
        ) => {

            if (!value) {

                return fallback;
            }


            return String(
                value
            )
                .replaceAll(
                    "_",
                    " "
                );
        };


    // ============================================================
    // ACTIONS
    // ============================================================

    const viewIncident =
        (
            incidentId
        ) => {

            navigate(
                `/incidents/${incidentId}`
            );
        };


    // ============================================================
    // INVESTIGATE DETECTED INCIDENT
    // ============================================================

    const investigateIncident =
        async (
            incident
        ) => {

            const incidentId =
                incident?.incident_id;


            if (!incidentId) {

                setError(
                    "Incident ID is missing."
                );

                return;
            }


            try {

                setError(
                    ""
                );

                setInvestigatingId(
                    incidentId
                );


                const result =
                    await investigateDetectedIncident(
                        incidentId
                    );


                if (
                    !result?.success
                ) {

                    throw new Error(
                        "Investigation did not complete successfully."
                    );
                }


                navigate(
                    `/incidents/${incidentId}`
                );


            } catch (err) {

                console.error(
                    "Incident investigation failed:",
                    err
                );


                setError(
                    err?.response?.data?.detail
                    || err?.message
                    || "Unable to investigate incident."
                );


            } finally {

                setInvestigatingId(
                    ""
                );
            }
        };


    // ============================================================
    // RENDER
    // ============================================================

    return (
        <div>

            <div className="page-heading">

                <div>

                    <h2>
                        Incidents
                    </h2>

                    <p>
                        Unified detection, correlation,
                        and persistent SENTINEL-X SOC incidents.
                    </p>

                </div>


                <div className="incident-count">

                    {filteredIncidents.length}

                    {" "}

                    incidents

                </div>

            </div>


            <section className="filter-panel">

                <div className="filter-group">

                    <label>
                        Risk Level
                    </label>


                    <select
                        value={riskLevel}
                        onChange={
                            (event) =>
                                setRiskLevel(
                                    event.target.value
                                )
                        }
                    >

                        <option value="">
                            All
                        </option>

                        <option value="CRITICAL">
                            Critical
                        </option>

                        <option value="HIGH">
                            High
                        </option>

                        <option value="MEDIUM">
                            Medium
                        </option>

                        <option value="LOW">
                            Low
                        </option>

                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Lifecycle Status
                    </label>


                    <select
                        value={status}
                        onChange={
                            (event) =>
                                setStatus(
                                    event.target.value
                                )
                        }
                    >

                        <option value="">
                            All
                        </option>

                        <option value="DETECTED_ONLY">
                            Detected / Not Investigated
                        </option>

                        <option value="AWAITING_ANALYST_REVIEW">
                            Awaiting Review
                        </option>

                        <option value="APPROVED">
                            Approved
                        </option>

                        <option value="REJECTED">
                            Rejected
                        </option>

                        <option value="RESOLVED">
                            Resolved
                        </option>

                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Minimum Risk Score
                    </label>


                    <input
                        type="number"
                        min="0"
                        max="100"
                        placeholder="0"
                        value={minRisk}
                        onChange={
                            (event) =>
                                setMinRisk(
                                    event.target.value
                                )
                        }
                    />

                </div>


                <div className="filter-actions">

                    <button
                        className="primary-button"
                        onClick={
                            loadIncidents
                        }
                    >
                        Refresh
                    </button>


                    <button
                        className="secondary-button"
                        onClick={
                            clearFilters
                        }
                    >
                        Clear
                    </button>

                </div>

            </section>


            {loading && (

                <div className="message-card">
                    Loading incidents...
                </div>
            )}


            {error && (

                <div className="message-card error">
                    {error}
                </div>
            )}


            {!loading
                && filteredIncidents.length === 0
                && (

                    <div className="message-card">

                        No incidents match
                        the selected filters.

                    </div>
                )}


            {!loading
                && filteredIncidents.length > 0
                && (

                    <div className="table-container">

                        <table className="soc-table">

                            <thead>

                                <tr>

                                    <th>
                                        Incident
                                    </th>

                                    <th>
                                        Source
                                    </th>

                                    <th>
                                        Correlation
                                    </th>

                                    <th>
                                        Risk / Severity
                                    </th>

                                    <th>
                                        Events
                                    </th>

                                    <th>
                                        SOC Status
                                    </th>

                                    <th>
                                        Approval
                                    </th>

                                    <th>
                                        Mitigation
                                    </th>

                                    <th>
                                        Created
                                    </th>

                                    <th>
                                        Action
                                    </th>

                                </tr>

                            </thead>


                            <tbody>

                                {filteredIncidents.map(
                                    (incident) => {

                                        const incidentId =
                                            incident.incident_id;


                                        const riskLabel =
                                            incident.risk_level
                                            || incident.severity
                                            || "UNKNOWN";


                                        return (

                                            <tr
                                                key={
                                                    incidentId
                                                }
                                            >

                                                <td className="incident-id-cell">

                                                    <div>
                                                        {incidentId}
                                                    </div>

                                                    {incident.title
                                                        && incident.title !== incidentId
                                                        && (

                                                            <small>
                                                                {incident.title}
                                                            </small>
                                                        )}

                                                </td>


                                                <td>

                                                    <span className="badge neutral">
                                                        {incident.source}
                                                    </span>

                                                </td>


                                                <td>
                                                    {formatCorrelation(
                                                        incident.correlation_score
                                                    )}
                                                </td>


                                                <td>

                                                    <span
                                                        className={
                                                            getRiskClass(
                                                                riskLabel
                                                            )
                                                        }
                                                    >
                                                        {riskLabel}
                                                    </span>

                                                    {incident.risk_score !== null
                                                        && incident.risk_score !== undefined
                                                        && (

                                                            <>
                                                                {" "}
                                                                <strong>
                                                                    {incident.risk_score}
                                                                </strong>
                                                            </>
                                                        )}

                                                </td>


                                                <td>
                                                    {incident.event_count ?? 0}
                                                </td>


                                                <td>

                                                    <span className="badge neutral">

                                                        {
                                                            incident.soc_case_exists
                                                                ? formatStatus(
                                                                    incident.soc_case_status
                                                                    || incident.case_status,
                                                                    "SOC CASE"
                                                                )
                                                                : "NOT CREATED"
                                                        }

                                                    </span>

                                                </td>


                                                <td>

                                                    <span className="badge neutral">

                                                        {
                                                            incident.soc_case_exists
                                                                ? formatStatus(
                                                                    incident.approval_status,
                                                                    "PENDING"
                                                                )
                                                                : "-"
                                                        }

                                                    </span>

                                                </td>


                                                <td>

                                                    <span className="badge neutral">

                                                        {
                                                            incident.soc_case_exists
                                                                ? formatStatus(
                                                                    incident.mitigation_status,
                                                                    "NOT VERIFIED"
                                                                )
                                                                : "-"
                                                        }

                                                    </span>

                                                </td>


                                                <td>
                                                    {formatDate(
                                                        incident.created_at
                                                    )}
                                                </td>


                                                <td>

                                                    {incident.soc_case_exists
                                                        ? (

                                                            <button
                                                                className="table-action-button"
                                                                onClick={
                                                                    () =>
                                                                        viewIncident(
                                                                            incidentId
                                                                        )
                                                                }
                                                            >
                                                                View
                                                            </button>

                                                        )
                                                        : (

                                                            <button
                                                                className="table-action-button"
                                                                disabled={
                                                                    investigatingId
                                                                    === incidentId
                                                                }
                                                                onClick={
                                                                    () =>
                                                                        investigateIncident(
                                                                            incident
                                                                        )
                                                                }
                                                            >
                                                                {
                                                                    investigatingId
                                                                    === incidentId
                                                                        ? "Investigating..."
                                                                        : "Investigate"
                                                                }
                                                            </button>
                                                        )}

                                                </td>

                                            </tr>
                                        );
                                    }
                                )}

                            </tbody>

                        </table>

                    </div>
                )}

        </div>
    );
}


export default Incidents;