import {
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
    useParams,
} from "react-router-dom";

import {
    getFullIncident,
    getMitigationVerification,
} from "../api/sentinelApi";

import EvidencePanel from "../components/incidents/EvidencePanel";
import TimelinePanel from "../components/incidents/TimelinePanel";
import AgentIntelligencePanel from "../components/incidents/AgentIntelligencePanel";
import AnalystDecisionPanel from "../components/incidents/AnalystDecisionPanel";
import PlanComparison from "../components/digitalTwin/PlanComparison";


// ================================================================
// HELPERS
// ================================================================

function safeObject(
    value
) {
    return (
        value
        && typeof value === "object"
        && !Array.isArray(value)
    )
        ? value
        : {};
}


function safeArray(
    value
) {
    return Array.isArray(value)
        ? value
        : [];
}


function formatValue(
    value,
    fallback = "-"
) {
    if (
        value === null
        || value === undefined
        || value === ""
    ) {
        return fallback;
    }

    if (
        typeof value === "object"
        && !Array.isArray(value)
    ) {
        if (value.impact_level) {
            return value.impact_level;
        }

        if (value.status) {
            return value.status;
        }

        if (value.plan_name) {
            return value.plan_name;
        }

        if (value.name) {
            return value.name;
        }

        try {
            return JSON.stringify(value);
        } catch {
            return fallback;
        }
    }

    if (Array.isArray(value)) {
        return value.length > 0
            ? value
                .map(
                    (item) =>
                        typeof item === "object"
                            ? JSON.stringify(item)
                            : String(item)
                )
                .join(", ")
            : fallback;
    }

    return value;
}


function formatOperationalImpact(
    value,
    fallback = "-"
) {
    if (
        value === null
        || value === undefined
        || value === ""
    ) {
        return fallback;
    }

    if (
        typeof value === "object"
        && !Array.isArray(value)
    ) {
        return (
            value.impact_level
            || value.level
            || value.status
            || fallback
        );
    }

    return String(value);
}


function sanitizePlanForRendering(
    plan
) {
    const data =
        safeObject(
            plan
        );

    if (
        Object.keys(data).length
        === 0
    ) {
        return {};
    }

    return {
        ...data,

        operational_impact:
            formatOperationalImpact(
                data.operational_impact,
                "-"
            ),
    };
}


function formatPercentage(
    value
) {
    if (
        value === null
        || value === undefined
        || value === ""
    ) {
        return "Not applicable";
    }

    const text =
        String(value);

    if (
        text.includes("%")
    ) {
        return text;
    }

    return `${value}%`;
}


function formatDate(
    value
) {
    if (!value) {
        return "-";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleString();
}


function riskClass(
    level
) {
    const value =
        String(
            level || ""
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
        || value === "INFO"
    ) {
        return "badge low";
    }

    return "badge neutral";
}


function statusClass(
    value
) {
    const status =
        String(
            value || ""
        ).toUpperCase();

    if (
        status === "APPROVED"
        || status === "VERIFIED"
        || status === "SIMULATION_VERIFIED"
        || status === "NOT_REQUIRED"
        || status === "SUCCESS"
    ) {
        return "badge low";
    }

    if (
        status === "REJECTED"
        || status === "FAILED"
        || status === "SIMULATION_NO_IMPROVEMENT"
    ) {
        return "badge critical";
    }

    if (
        status === "PENDING"
        || status === "AWAITING_APPROVAL"
        || status === "AWAITING_ANALYST_REVIEW"
        || status === "PARTIAL"
        || status === "SIMULATION_PARTIAL"
    ) {
        return "badge high";
    }

    return "badge neutral";
}


function getEvidenceCount(
    evidence
) {
    const data =
        safeObject(
            evidence
        );

    return (
        safeArray(
            data.processes
        ).length
        +
        safeArray(
            data.files
        ).length
        +
        safeArray(
            data.network_connections
        ).length
        +
        safeArray(
            data.registry_artifacts
        ).length
    );
}


// ================================================================
// SUMMARY CARD
// ================================================================

function SummaryCard({
    title,
    children,
}) {
    return (
        <div className="summary-card">

            <span>
                {title}
            </span>

            <div>
                {children}
            </div>

        </div>
    );
}


// ================================================================
// DETAIL ROW
// ================================================================

function DetailRow({
    label,
    children,
}) {
    return (
        <div>

            <span>
                {label}
            </span>

            <strong>
                {children}
            </strong>

        </div>
    );
}


// ================================================================
// EMPTY PANEL
// ================================================================

function EmptyPanel({
    title,
    subtitle,
    message,
}) {
    return (
        <section className="detail-panel full-width-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        {title}
                    </h3>

                    {subtitle && (
                        <p>
                            {subtitle}
                        </p>
                    )}

                </div>

            </div>

            <div className="empty-inline">
                {message}
            </div>

        </section>
    );
}


// ================================================================
// INCIDENT DETAIL
// ================================================================

function IncidentDetail() {

    const {
        incidentId,
    } = useParams();

    const navigate =
        useNavigate();


    const [
        incident,
        setIncident,
    ] = useState(null);


    const [
        mitigation,
        setMitigation,
    ] = useState(null);


    const [
        loading,
        setLoading,
    ] = useState(true);


    const [
        error,
        setError,
    ] = useState("");


    // ============================================================
    // LOAD INCIDENT
    // ============================================================

    const loadIncident =
        async () => {

            try {

                setLoading(
                    true
                );

                setError(
                    ""
                );


                // ------------------------------------------------
                // Full incident is required.
                // Mitigation verification is optional because a
                // case may not have been verified yet.
                // ------------------------------------------------

                const [
                    incidentResult,
                    mitigationResult,
                ] = await Promise.allSettled([

                    getFullIncident(
                        incidentId
                    ),

                    getMitigationVerification(
                        incidentId
                    ),
                ]);


                if (
                    incidentResult.status
                    !== "fulfilled"
                ) {
                    throw incidentResult.reason;
                }


                setIncident(
                    incidentResult.value
                    || null
                );


                if (
                    mitigationResult.status
                    === "fulfilled"
                ) {
                    setMitigation(
                        mitigationResult.value
                        || null
                    );
                } else {
                    setMitigation(
                        null
                    );
                }


            } catch (
                err
            ) {

                console.error(
                    "Incident detail loading failed:",
                    err
                );


                setError(
                    err?.response
                        ?.data
                        ?.detail
                    || err?.message
                    || "Unable to load incident details."
                );


            } finally {

                setLoading(
                    false
                );
            }
        };


    // ============================================================
    // INITIAL LOAD
    // ============================================================

    useEffect(
        () => {

            loadIncident();

        },
        [
            incidentId,
        ]
    );


    // ============================================================
    // LOADING
    // ============================================================

    if (
        loading
        && !incident
    ) {
        return (
            <div className="message-card">
                Loading incident investigation...
            </div>
        );
    }


    // ============================================================
    // ERROR
    // ============================================================

    if (
        error
        && !incident
    ) {
        return (
            <div className="message-card error">

                <h3>
                    Incident unavailable
                </h3>

                <p>
                    {error}
                </p>

                <button
                    className="secondary-button"
                    onClick={
                        () =>
                            navigate(
                                "/incidents"
                            )
                    }
                >
                    Back to Incidents
                </button>

            </div>
        );
    }


    // ============================================================
    // INCIDENT MISSING
    // ============================================================

    if (!incident) {
        return (
            <div className="message-card">
                Incident data is not available.
            </div>
        );
    }


    // ============================================================
    // NORMALIZED INCIDENT DATA
    // ============================================================

    const risk =
        safeObject(
            incident.risk
        );


    const evidence =
        safeObject(
            incident.evidence
        );


    const timeline =
        safeObject(
            incident.timeline
        );


    const intelligence =
        safeObject(
            incident.intelligence
        );


    const intelligenceData =
        safeObject(
            intelligence.data
        );


    const digitalTwin =
        safeObject(
            incident.digital_twin
        );


    const explanation =
        safeObject(
            incident.explanation
        );


    const ticket =
        safeObject(
            incident.ticket
        );


    const response =
        safeObject(
            incident.response
        );


    const safety =
        safeObject(
            incident.safety
        );


    const persistence =
        safeObject(
            incident.persistence
        );


    const selectedPlan =
        safeObject(
            digitalTwin.selected_plan
        );


    const candidatePlans =
        safeArray(
            digitalTwin.candidate_plans
        );


    // ============================================================
    // SAFE DIGITAL TWIN DATA FOR CHILD COMPONENTS
    //
    // CRITICAL incidents contain structured operational_impact
    // objects. React cannot render plain objects directly, and an
    // older PlanComparison implementation may attempt to do so.
    // Convert those fields to readable strings before rendering.
    // ============================================================

    const safeSelectedPlan =
        sanitizePlanForRendering(
            selectedPlan
        );


    const safeCandidatePlans =
        candidatePlans.map(
            (
                plan
            ) =>
                sanitizePlanForRendering(
                    plan
                )
        );


    const safeRankedPlans =
        safeArray(
            digitalTwin.ranked_plans
        ).map(
            (
                plan
            ) =>
                sanitizePlanForRendering(
                    plan
                )
        );


    const safeBestPlan =
        sanitizePlanForRendering(
            digitalTwin.best_plan
        );


    const planComparisonTwin = {
        ...digitalTwin,

        selected_plan:
            safeSelectedPlan,

        best_plan:
            safeBestPlan,

        candidate_plans:
            safeCandidatePlans,

        ranked_plans:
            safeRankedPlans,
    };


    const actions =
        safeArray(
            response.actions
        );


    const timelineEvents =
        safeArray(
            timeline.events
        );


    const evidenceCount =
        getEvidenceCount(
            evidence
        );


    // ============================================================
    // DERIVED WORKFLOW STATE
    // ============================================================

    const decision =
        String(
            digitalTwin.decision
            || ""
        ).toUpperCase();


    const noResponsePlan =
        (
            decision
            === "NO_RESPONSE_PLAN_AVAILABLE"
        )
        || (
            candidatePlans.length === 0
            && Object.keys(
                selectedPlan
            ).length === 0
        );


    const approvalRequired =
        Boolean(
            digitalTwin
                .analyst_approval_required
        )
        ||
        Boolean(
            ticket
                .approval_required
        );


    const approvalStatus =
        String(
            ticket.approval_status
            || (
                approvalRequired
                    ? "PENDING"
                    : "NOT_REQUIRED"
            )
        ).toUpperCase();


    const showAnalystDecision =
        approvalRequired
        ||
        approvalStatus === "PENDING"
        ||
        approvalStatus
            === "AWAITING_APPROVAL";


    const intelligenceAvailable =
        intelligence.available
        === true
        &&
        Object.keys(
            intelligenceData
        ).length > 0;


    const mitigationStatus =
        String(

            mitigation?.status

            || mitigation
                ?.verification
                ?.status

            || "NOT_VERIFIED"

        ).toUpperCase();


    // ============================================================
    // PAGE
    // ============================================================

    return (
        <div>

            {/* ===================================================
                HEADER
               =================================================== */}

            <div className="page-heading">

                <div>

                    <h2>
                        Incident Investigation
                    </h2>

                    <p className="incident-detail-id">
                        {incident.incident_id}
                    </p>

                </div>


                <div
                    style={{
                        display:
                            "flex",
                        gap:
                            "10px",
                    }}
                >

                    <button
                        className="secondary-button"
                        onClick={
                            loadIncident
                        }
                        disabled={
                            loading
                        }
                    >
                        {
                            loading
                                ? "Refreshing..."
                                : "Refresh"
                        }
                    </button>


                    <button
                        className="secondary-button"
                        onClick={
                            () =>
                                navigate(
                                    "/incidents"
                                )
                        }
                    >
                        Back to Incidents
                    </button>

                </div>

            </div>


            {/* ===================================================
                OPTIONAL REFRESH ERROR
               =================================================== */}

            {
                error
                ? (
                    <div className="message-card error">
                        {error}
                    </div>
                )
                : null
            }


            {/* ===================================================
                WORKFLOW INTERPRETATION
               =================================================== */}

            {
                noResponsePlan
                && !approvalRequired
                ? (
                    <div className="approval-safety-banner">

                        <strong>
                            No Response Plan Required
                        </strong>

                        <span>

                            SENTINEL-X assessed this
                            incident at

                            {" "}

                            {
                                risk.initial_risk_level
                                || "INFO"
                            }

                            {" "}

                            risk with score

                            {" "}

                            {
                                formatValue(
                                    risk.initial_risk_score,
                                    "0"
                                )
                            }

                            . The Digital Twin produced
                            no response plan, no containment
                            approval is required, and no
                            response action has been executed.

                        </span>

                    </div>
                )
                : (
                    <div className="approval-safety-banner">

                        <strong>
                            Analyst-Supervised Incident
                        </strong>

                        <span>

                            Response recommendations remain
                            simulation-only. Real endpoint
                            modification is disabled.

                        </span>

                    </div>
                )
            }


            {/* ===================================================
                SUMMARY
               =================================================== */}

            <div className="incident-summary-grid">

                <SummaryCard
                    title="Case Status"
                >
                    <span
                        className={
                            statusClass(
                                incident.case_status
                            )
                        }
                    >
                        {
                            incident.case_status
                            || "UNKNOWN"
                        }
                    </span>
                </SummaryCard>


                <SummaryCard
                    title="Initial Risk"
                >
                    <strong>
                        {
                            formatValue(
                                risk.initial_risk_score
                            )
                        }
                    </strong>
                </SummaryCard>


                <SummaryCard
                    title="Risk Level"
                >
                    <span
                        className={
                            riskClass(
                                risk.initial_risk_level
                            )
                        }
                    >
                        {
                            risk.initial_risk_level
                            || "UNKNOWN"
                        }
                    </span>
                </SummaryCard>


                <SummaryCard
                    title="Digital Twin"
                >
                    <strong>
                        {
                            noResponsePlan
                                ? "NO RESPONSE PLAN"
                                : (
                                    digitalTwin.decision
                                    || "UNKNOWN"
                                )
                        }
                    </strong>
                </SummaryCard>


                <SummaryCard
                    title="Approval"
                >
                    <span
                        className={
                            statusClass(
                                approvalStatus
                            )
                        }
                    >
                        {
                            approvalStatus
                        }
                    </span>
                </SummaryCard>


                <SummaryCard
                    title="Response Actions"
                >
                    <strong>
                        {
                            response.action_count
                            ?? actions.length
                        }
                    </strong>
                </SummaryCard>

            </div>


            {/* ===================================================
                RISK + DIGITAL TWIN
               =================================================== */}

            <div className="incident-detail-grid">

                {/* ===============================================
                    RISK
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Risk Assessment
                            </h3>

                            <p>
                                Deterministic heuristic
                                incident risk reasoning.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <DetailRow
                            label="Initial Risk Score"
                        >
                            {
                                formatValue(
                                    risk.initial_risk_score
                                )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Risk Level"
                        >
                            {
                                risk.initial_risk_level
                                || "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Predicted Residual Risk"
                        >
                            {
                                formatValue(
                                    risk
                                        .predicted_residual_risk
                                )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Modeled Risk Reduction"
                        >
                            {
                                risk
                                    .modeled_risk_reduction
                                ?? (
                                    noResponsePlan
                                        ? "Not applicable"
                                        : "-"
                                )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Risk Reduction %"
                        >
                            {
                                noResponsePlan
                                    ? "Not applicable"
                                    : formatPercentage(
                                        risk
                                            .modeled_risk_reduction_percentage
                                    )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Model Type"
                        >
                            {
                                risk.model_type
                                || "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Calibrated Probability"
                        >
                            {
                                risk.calibrated_probability
                                === true
                                    ? "YES"
                                    : "NO"
                            }
                        </DetailRow>

                    </div>

                </section>


                {/* ===============================================
                    DIGITAL TWIN
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Digital Twin Decision
                            </h3>

                            <p>
                                Simulation-based response
                                planning and decision support.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <DetailRow
                            label="Decision"
                        >
                            {
                                digitalTwin.decision
                                || "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Selected Plan"
                        >
                            {
                                noResponsePlan
                                    ? "No Response Plan Selected"
                                    : (
                                        selectedPlan.plan_name
                                        || selectedPlan.name
                                        || ticket.selected_plan
                                        || "-"
                                    )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Candidate Plans"
                        >
                            {
                                digitalTwin
                                    .candidate_plan_count
                                ?? candidatePlans.length
                            }
                        </DetailRow>


                        <DetailRow
                            label="Predicted Residual Risk"
                        >
                            {
                                selectedPlan
                                    .predicted_residual_risk
                                ?? selectedPlan
                                    .residual_risk
                                ?? risk
                                    .predicted_residual_risk
                                ?? "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Risk Reduction"
                        >
                            {
                                noResponsePlan
                                    ? "Not applicable"
                                    : formatPercentage(
                                        selectedPlan
                                            .risk_reduction_percentage
                                        ?? selectedPlan
                                            .risk_reduction
                                    )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Operational Impact"
                        >
                            {
                                noResponsePlan
                                    ? "NONE"
                                    : formatOperationalImpact(
                                        selectedPlan
                                            .operational_impact
                                        ?? ticket
                                            .operational_impact
                                    )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Analyst Approval"
                        >
                            {
                                approvalRequired
                                    ? "REQUIRED"
                                    : "NOT REQUIRED"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Real Endpoint Modified"
                        >
                            <span
                                className="safe-disabled"
                            >
                                {
                                    digitalTwin
                                        .real_endpoint_modified
                                    ? "YES"
                                    : "NO"
                                }
                            </span>
                        </DetailRow>

                    </div>

                </section>

            </div>


            {/* ===================================================
                PLAN COMPARISON
               =================================================== */}

            {
                candidatePlans.length > 0
                ? (
                    <PlanComparison
                        digitalTwin={
                            planComparisonTwin
                        }
                    />
                )
                : (
                    <EmptyPanel
                        title="Digital Twin Plan Comparison"
                        subtitle={
                            "Candidate response plans "
                            + "evaluated by the Digital Twin."
                        }
                        message={
                            "No candidate response plans "
                            + "were generated for this "
                            + "incident because the current "
                            + "risk assessment did not "
                            + "produce a response plan."
                        }
                    />
                )
            }


            {/* ===================================================
                ANALYST DECISION
               =================================================== */}

            {
                showAnalystDecision
                ? (
                    <AnalystDecisionPanel
                        incidentId={
                            incident.incident_id
                        }
                        caseStatus={
                            incident.case_status
                        }
                        approvalStatus={
                            approvalStatus
                        }
                        onDecisionComplete={
                            loadIncident
                        }
                    />
                )
                : (
                    <EmptyPanel
                        title="Analyst Response Approval"
                        subtitle={
                            "Human approval state for "
                            + "recommended response actions."
                        }
                        message={
                            "No response approval is "
                            + "required for this incident. "
                            + "The Digital Twin did not "
                            + "select a response plan and "
                            + "there are no response "
                            + "actions awaiting execution."
                        }
                    />
                )
            }


            {/* ===================================================
                EVIDENCE
               =================================================== */}

            {
                evidenceCount > 0
                ? (
                    <EvidencePanel
                        evidence={
                            evidence
                        }
                    />
                )
                : (
                    <EmptyPanel
                        title="Investigation Evidence"
                        subtitle={
                            "Persisted process, file, "
                            + "network and registry "
                            + "artifacts."
                        }
                        message={
                            "No investigation evidence "
                            + "artifacts were persisted "
                            + "for this SOC case. This "
                            + "does not indicate that the "
                            + "endpoint database contains "
                            + "no telemetry; it only means "
                            + "this case currently has no "
                            + "persisted evidence artifacts."
                        }
                    />
                )
            }


            {/* ===================================================
                TIMELINE
               =================================================== */}

            {
                timelineEvents.length > 0
                ? (
                    <TimelinePanel
                        timeline={
                            timeline
                        }
                    />
                )
                : (
                    <EmptyPanel
                        title="Attack Timeline"
                        subtitle={
                            "Persisted chronological "
                            + "incident activity."
                        }
                        message={
                            "No attack timeline events "
                            + "were persisted for this "
                            + "SOC case."
                        }
                    />
                )
            }


            {/* ===================================================
                MULTI-AGENT INTELLIGENCE
               =================================================== */}

            {
                intelligenceAvailable
                ? (
                    <AgentIntelligencePanel
                        intelligence={
                            intelligence
                        }
                    />
                )
                : (
                    <EmptyPanel
                        title="Multi-Agent Intelligence"
                        subtitle={
                            "Investigation and reasoning "
                            + "persisted from SENTINEL-X "
                            + "agents."
                        }
                        message={
                            "No additional multi-agent "
                            + "intelligence payload is "
                            + "available in the persisted "
                            + "full incident view for "
                            + "this case."
                        }
                    />
                )
            }


            {/* ===================================================
                EXPLANATION
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Decision Explanation
                        </h3>

                        <p>
                            Human-readable explanation of
                            the Digital Twin decision.
                        </p>

                    </div>

                </div>


                {
                    Object.keys(
                        explanation
                    ).length > 0
                        ? (
                            <>
                                <div className="detail-list">

                                    <DetailRow
                                        label="Status"
                                    >
                                        {
                                            explanation.status
                                            || "-"
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Summary"
                                    >
                                        {
                                            formatValue(
                                                explanation.summary
                                            )
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Explainability Engine"
                                    >
                                        {
                                            explanation.explainability
                                            || "-"
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Generated At"
                                    >
                                        {
                                            formatDate(
                                                explanation
                                                    .generated_at
                                            )
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Real Endpoint Modified"
                                    >
                                        <span
                                            className="safe-disabled"
                                        >
                                            {
                                                explanation
                                                    .real_endpoint_modified
                                                ? "YES"
                                                : "NO"
                                            }
                                        </span>
                                    </DetailRow>

                                </div>


                                <details
                                    className="timeline-details"
                                    style={{
                                        marginTop:
                                            "16px",
                                    }}
                                >
                                    <summary>
                                        View raw explanation
                                    </summary>

                                    <pre
                                        className="incident-json-block"
                                    >
                                        {
                                            JSON.stringify(
                                                explanation,
                                                null,
                                                2
                                            )
                                        }
                                    </pre>
                                </details>
                            </>
                        )
                        : (
                            <div className="empty-inline">
                                No explanation data available.
                            </div>
                        )
                }

            </section>


            {/* ===================================================
                TICKET + SAFETY
               =================================================== */}

            <div className="incident-detail-grid">

                {/* ===============================================
                    TICKET
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                SOC Ticket
                            </h3>

                            <p>
                                Persistent ticket associated
                                with this incident.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <DetailRow
                            label="Ticket ID"
                        >
                            {
                                ticket.ticket_id
                                || "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Priority"
                        >
                            {
                                ticket.priority
                                || "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Risk Score"
                        >
                            {
                                formatValue(
                                    ticket.risk_score
                                )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Risk Level"
                        >
                            {
                                ticket.risk_level
                                || "-"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Selected Plan"
                        >
                            {
                                ticket.selected_plan
                                || (
                                    noResponsePlan
                                        ? "No Response Plan Selected"
                                        : "-"
                                )
                            }
                        </DetailRow>


                        <DetailRow
                            label="Status"
                        >
                            <span
                                className={
                                    statusClass(
                                        ticket.status
                                    )
                                }
                            >
                                {
                                    ticket.status
                                    || "-"
                                }
                            </span>
                        </DetailRow>


                        <DetailRow
                            label="Approval Required"
                        >
                            {
                                approvalRequired
                                    ? "YES"
                                    : "NO"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Approval Status"
                        >
                            <span
                                className={
                                    statusClass(
                                        approvalStatus
                                    )
                                }
                            >
                                {
                                    approvalStatus
                                }
                            </span>
                        </DetailRow>


                        <DetailRow
                            label="Assigned Analyst"
                        >
                            {
                                ticket.assigned_analyst
                                || "Not assigned"
                            }
                        </DetailRow>

                    </div>

                </section>


                {/* ===============================================
                    SAFETY
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Safety State
                            </h3>

                            <p>
                                SENTINEL-X response execution
                                safeguards.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <DetailRow
                            label="Simulation Mode"
                        >
                            {
                                safety.simulation_mode
                                    ? "ENABLED"
                                    : "DISABLED"
                            }
                        </DetailRow>


                        <DetailRow
                            label="Real Endpoint Modified"
                        >
                            <span
                                className="safe-disabled"
                            >
                                {
                                    safety
                                        .real_endpoint_modified
                                    ? "YES"
                                    : "NO"
                                }
                            </span>
                        </DetailRow>


                        <DetailRow
                            label="Real Response Executed"
                        >
                            <span
                                className="safe-disabled"
                            >
                                {
                                    safety
                                        .real_response_executed
                                    ? "YES"
                                    : "NO"
                                }
                            </span>
                        </DetailRow>


                        <DetailRow
                            label="Response Actions"
                        >
                            {
                                response.action_count
                                ?? actions.length
                            }
                        </DetailRow>


                        <DetailRow
                            label="Approved Actions"
                        >
                            {
                                response
                                    .approval_counts
                                    ?.APPROVED
                                ?? 0
                            }
                        </DetailRow>


                        <DetailRow
                            label="Pending Actions"
                        >
                            {
                                response
                                    .approval_counts
                                    ?.PENDING
                                ?? 0
                            }
                        </DetailRow>


                        <DetailRow
                            label="Ready Actions"
                        >
                            {
                                response
                                    .execution_counts
                                    ?.READY
                                ?? 0
                            }
                        </DetailRow>

                    </div>

                </section>

            </div>


            {/* ===================================================
                RESPONSE ACTIONS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Response Actions
                        </h3>

                        <p>
                            Policy-controlled simulated
                            response actions generated for
                            the incident.
                        </p>

                    </div>


                    <div className="timeline-count">

                        {
                            actions.length
                        }

                        {" "}

                        actions

                    </div>

                </div>


                {
                    actions.length === 0
                        ? (
                            <div className="empty-inline">

                                {
                                    noResponsePlan
                                        ? (
                                            <>
                                                No response actions were
                                                generated because the
                                                Digital Twin selected no
                                                response plan for the
                                                current assessed risk.
                                            </>
                                        )
                                        : (
                                            <>
                                                No response actions are
                                                available for this
                                                incident.
                                            </>
                                        )
                                }

                            </div>
                        )
                        : (
                            <div
                                className={
                                    "table-container "
                                    + "response-table-wrap"
                                }
                            >

                                <table className="soc-table">

                                    <thead>

                                        <tr>

                                            <th>
                                                Action
                                            </th>

                                            <th>
                                                Risk
                                            </th>

                                            <th>
                                                Approval
                                            </th>

                                            <th>
                                                Execution
                                            </th>

                                            <th>
                                                Approval Required
                                            </th>

                                            <th>
                                                Requested By
                                            </th>

                                        </tr>

                                    </thead>


                                    <tbody>

                                        {
                                            actions.map(
                                                (
                                                    action,
                                                    index
                                                ) => (

                                                    <tr
                                                        key={
                                                            action
                                                                .action_id
                                                            || index
                                                        }
                                                    >

                                                        <td>
                                                            <strong>
                                                                {
                                                                    action
                                                                        .action_type
                                                                    || "-"
                                                                }
                                                            </strong>
                                                        </td>


                                                        <td>

                                                            <span
                                                                className={
                                                                    riskClass(
                                                                        action
                                                                            .risk_level
                                                                    )
                                                                }
                                                            >
                                                                {
                                                                    action
                                                                        .risk_level
                                                                    || "-"
                                                                }
                                                            </span>

                                                        </td>


                                                        <td>

                                                            <span
                                                                className={
                                                                    statusClass(
                                                                        action
                                                                            .approval_status
                                                                    )
                                                                }
                                                            >
                                                                {
                                                                    action
                                                                        .approval_status
                                                                    || "-"
                                                                }
                                                            </span>

                                                        </td>


                                                        <td>

                                                            <span
                                                                className={
                                                                    statusClass(
                                                                        action
                                                                            .execution_status
                                                                    )
                                                                }
                                                            >
                                                                {
                                                                    action
                                                                        .execution_status
                                                                    || "-"
                                                                }
                                                            </span>

                                                        </td>


                                                        <td>
                                                            {
                                                                action
                                                                    .approval_required
                                                                ? "YES"
                                                                : "NO"
                                                            }
                                                        </td>


                                                        <td>
                                                            {
                                                                action
                                                                    .requested_by
                                                                || "-"
                                                            }
                                                        </td>

                                                    </tr>
                                                )
                                            )
                                        }

                                    </tbody>

                                </table>

                            </div>
                        )
                }

            </section>


            {/* ===================================================
                MITIGATION VERIFICATION
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Mitigation Verification
                        </h3>

                        <p>
                            Verification state for simulated
                            mitigation outcomes.
                        </p>

                    </div>

                </div>


                {
                    mitigation
                        ? (
                            <>
                                <div className="detail-list">

                                    <DetailRow
                                        label="Status"
                                    >
                                        <span
                                            className={
                                                statusClass(
                                                    mitigationStatus
                                                )
                                            }
                                        >
                                            {
                                                mitigationStatus
                                            }
                                        </span>
                                    </DetailRow>


                                    <DetailRow
                                        label="Verification Type"
                                    >
                                        {
                                            mitigation
                                                .verification_type
                                            || mitigation
                                                .verification
                                                ?.verification_type
                                            || "-"
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Overall Improvement"
                                    >
                                        {
                                            mitigation
                                                .overall_improvement
                                            ?? mitigation
                                                .verification
                                                ?.overall_improvement
                                            ?? "-"
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Residual Risk"
                                    >
                                        {
                                            mitigation
                                                .residual_risk
                                            ?? mitigation
                                                .verification
                                                ?.residual_risk
                                            ?? "-"
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Simulation Mode"
                                    >
                                        {
                                            (
                                                mitigation
                                                    .simulation_mode
                                                ?? true
                                            )
                                                ? "ENABLED"
                                                : "DISABLED"
                                        }
                                    </DetailRow>


                                    <DetailRow
                                        label="Real Response Executed"
                                    >
                                        <span
                                            className="safe-disabled"
                                        >
                                            {
                                                mitigation
                                                    .real_response_executed
                                                ? "YES"
                                                : "NO"
                                            }
                                        </span>
                                    </DetailRow>

                                </div>


                                <details
                                    className="timeline-details"
                                    style={{
                                        marginTop:
                                            "16px",
                                    }}
                                >
                                    <summary>
                                        View mitigation details
                                    </summary>

                                    <pre
                                        className="incident-json-block"
                                    >
                                        {
                                            JSON.stringify(
                                                mitigation,
                                                null,
                                                2
                                            )
                                        }
                                    </pre>
                                </details>
                            </>
                        )
                        : (
                            <div className="empty-inline">

                                Mitigation verification has
                                not been performed for this
                                incident.

                            </div>
                        )
                }

            </section>


            {/* ===================================================
                PERSISTENCE
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Persistence State
                        </h3>

                        <p>
                            Persistent SOC case storage
                            information.
                        </p>

                    </div>

                </div>


                <div className="detail-list">

                    <DetailRow
                        label="Recovered From Database"
                    >
                        {
                            persistence
                                .recovered_from_database
                            ? "YES"
                            : "NO"
                        }
                    </DetailRow>


                    <DetailRow
                        label="Created At"
                    >
                        {
                            formatDate(
                                persistence.created_at
                            )
                        }
                    </DetailRow>


                    <DetailRow
                        label="Updated At"
                    >
                        {
                            formatDate(
                                persistence.updated_at
                            )
                        }
                    </DetailRow>

                </div>

            </section>


            {/* ===================================================
                MODEL NOTE
               =================================================== */}

            <div className="digital-twin-note">

                <strong>
                    Interpretation:
                </strong>

                {" "}

                Risk scores, residual-risk values and
                Digital Twin plan scores are
                deterministic heuristic
                decision-support values used by the
                SENTINEL-X prototype. They are not
                calibrated real-world probabilities.
                All response execution remains
                simulation-only.

            </div>

        </div>
    );
}


export default IncidentDetail;