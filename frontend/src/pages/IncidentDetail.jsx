import {
    useEffect,
    useState,
} from "react";

import {
    useParams,
    useNavigate,
} from "react-router-dom";

import {
    getFullIncident,
} from "../api/sentinelApi";

import EvidencePanel from "../components/incidents/EvidencePanel";
import TimelinePanel from "../components/incidents/TimelinePanel";
import PlanComparison from "../components/digitalTwin/PlanComparison";


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

    const loadIncident = async () => {

        try {

            setLoading(true);

            const data =
                await getFullIncident(
                    incidentId
                );


            setIncident(
                data
            );


            setError("");

        } catch (err) {

            console.error(
                "Incident detail loading failed:",
                err
            );


            setError(
                "Unable to load incident details."
            );

        } finally {

            setLoading(false);
        }
    };


    // ============================================================
    // LOAD ON PAGE OPEN
    // ============================================================

    useEffect(() => {

        loadIncident();

    }, [incidentId]);


    // ============================================================
    // HELPERS
    // ============================================================

    const formatValue = (
        value
    ) => {

        if (
            value === null
            || value === undefined
            || value === ""
        ) {

            return "-";
        }


        return value;
    };


    const formatPercentage = (
        value
    ) => {

        if (
            value === null
            || value === undefined
            || value === ""
        ) {

            return "-";
        }


        const text =
            String(
                value
            );


        if (
            text.includes("%")
        ) {

            return text;
        }


        return `${value}%`;
    };


    const riskClass = (
        level
    ) => {

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
        ) {

            return "badge low";
        }


        return "badge neutral";
    };


    const statusClass = (
        value
    ) => {

        const status =
            String(
                value || ""
            ).toUpperCase();


        if (
            status === "APPROVED"
        ) {

            return "badge low";
        }


        if (
            status === "REJECTED"
        ) {

            return "badge critical";
        }


        if (
            status === "PENDING"
            || status === "AWAITING_APPROVAL"
            || status === "AWAITING_ANALYST_REVIEW"
        ) {

            return "badge high";
        }


        return "badge neutral";
    };


    // ============================================================
    // LOADING
    // ============================================================

    if (loading) {

        return (

            <div className="message-card">

                Loading incident investigation...

            </div>
        );
    }


    // ============================================================
    // ERROR
    // ============================================================

    if (error) {

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
    // INCIDENT NOT AVAILABLE
    // ============================================================

    if (!incident) {

        return (

            <div className="message-card">

                Incident data is not available.

            </div>
        );
    }


    // ============================================================
    // INCIDENT SECTIONS
    // ============================================================

    const risk =
        incident.risk || {};


    const evidence =
        incident.evidence || {};


    const timeline =
        incident.timeline || {};


    const digitalTwin =
        incident.digital_twin || {};


    const ticket =
        incident.ticket || {};


    const response =
        incident.response || {};


    const safety =
        incident.safety || {};


    const explanation =
        incident.explanation || {};


    const intelligence =
        incident.intelligence || {};


    const selectedPlan =
        digitalTwin.selected_plan || {};


    const actions =
        response.actions || [];


    // ============================================================
    // PAGE
    // ============================================================

    return (

        <div>

            {/* ===================================================
                PAGE HEADER
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
                        display: "flex",
                        gap: "10px",
                    }}
                >

                    <button
                        className="secondary-button"
                        onClick={
                            loadIncident
                        }
                    >
                        Refresh
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
                SUMMARY CARDS
               =================================================== */}

            <div className="incident-summary-grid">

                <div className="summary-card">

                    <span>
                        Case Status
                    </span>


                    <div>

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

                    </div>

                </div>


                <div className="summary-card">

                    <span>
                        Initial Risk
                    </span>


                    <strong>
                        {
                            formatValue(
                                risk.initial_risk_score
                            )
                        }
                    </strong>

                </div>


                <div className="summary-card">

                    <span>
                        Risk Level
                    </span>


                    <div>

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

                    </div>

                </div>


                <div className="summary-card">

                    <span>
                        Residual Risk
                    </span>


                    <strong>
                        {
                            formatValue(
                                risk.predicted_residual_risk
                            )
                        }
                    </strong>

                </div>


                <div className="summary-card">

                    <span>
                        Ticket Priority
                    </span>


                    <strong>
                        {
                            ticket.priority
                            || "-"
                        }
                    </strong>

                </div>


                <div className="summary-card">

                    <span>
                        Approval
                    </span>


                    <div>

                        <span
                            className={
                                statusClass(
                                    ticket.approval_status
                                )
                            }
                        >

                            {
                                ticket.approval_status
                                || "-"
                            }

                        </span>

                    </div>

                </div>

            </div>


            {/* ===================================================
                RISK + DIGITAL TWIN SUMMARY
               =================================================== */}

            <div className="incident-detail-grid">

                {/* ===============================================
                    RISK ASSESSMENT
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

                        <div>

                            <span>
                                Initial Risk Score
                            </span>


                            <strong>
                                {
                                    formatValue(
                                        risk.initial_risk_score
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Risk Level
                            </span>


                            <strong>
                                {
                                    risk.initial_risk_level
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Predicted Residual Risk
                            </span>


                            <strong>
                                {
                                    formatValue(
                                        risk.predicted_residual_risk
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Modeled Risk Reduction
                            </span>


                            <strong>
                                {
                                    formatValue(
                                        risk.modeled_risk_reduction
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Risk Reduction %
                            </span>


                            <strong>
                                {
                                    formatPercentage(
                                        risk
                                            .modeled_risk_reduction_percentage
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Model Type
                            </span>


                            <strong>
                                {
                                    risk.model_type
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Calibrated Probability
                            </span>


                            <strong>
                                {
                                    risk.calibrated_probability
                                    === true
                                        ? "YES"
                                        : "NO"
                                }
                            </strong>

                        </div>

                    </div>

                </section>


                {/* ===============================================
                    DIGITAL TWIN SUMMARY
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Digital Twin Decision
                            </h3>


                            <p>
                                Response planning using
                                virtual endpoint simulation.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <div>

                            <span>
                                Decision
                            </span>


                            <strong>
                                {
                                    digitalTwin.decision
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Selected Plan
                            </span>


                            <strong>
                                {
                                    selectedPlan.plan_name
                                    || selectedPlan.name
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Predicted Residual Risk
                            </span>


                            <strong>
                                {
                                    formatValue(
                                        selectedPlan
                                            .predicted_residual_risk
                                        ?? selectedPlan
                                            .residual_risk
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Risk Reduction
                            </span>


                            <strong>
                                {
                                    formatPercentage(
                                        selectedPlan
                                            .risk_reduction_percentage
                                        ?? selectedPlan
                                            .risk_reduction
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Operational Impact
                            </span>


                            <strong>
                                {
                                    selectedPlan
                                        .operational_impact
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Plan Score
                            </span>


                            <strong>
                                {
                                    formatValue(
                                        selectedPlan.score
                                        ?? selectedPlan.plan_score
                                        ?? selectedPlan.security_score
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Candidate Plans
                            </span>


                            <strong>
                                {
                                    digitalTwin
                                        .candidate_plan_count
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Analyst Approval
                            </span>


                            <strong>
                                {
                                    digitalTwin
                                        .analyst_approval_required
                                    ? "REQUIRED"
                                    : "NOT REQUIRED"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Real Endpoint Modified
                            </span>


                            <strong className="safe-disabled">

                                {
                                    digitalTwin
                                        .real_endpoint_modified
                                    ? "YES"
                                    : "NO"
                                }

                            </strong>

                        </div>

                    </div>

                </section>

            </div>


            {/* ===================================================
                DIGITAL TWIN PLAN COMPARISON
               =================================================== */}

            <PlanComparison
                digitalTwin={
                    digitalTwin
                }
            />


            {/* ===================================================
                EVIDENCE
               =================================================== */}

            <EvidencePanel
                evidence={
                    evidence
                }
            />


            {/* ===================================================
                ATTACK TIMELINE
               =================================================== */}

            <TimelinePanel
                timeline={
                    timeline
                }
            />


            {/* ===================================================
                INTELLIGENCE / EXPLANATION
               =================================================== */}

            <div className="incident-detail-grid">

                {/* ===============================================
                    INTELLIGENCE
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Multi-Agent Intelligence
                            </h3>


                            <p>
                                Investigation and reasoning
                                generated by SENTINEL-X agents.
                            </p>

                        </div>

                    </div>


                    {
                        intelligence.available
                        === true
                        ? (

                            <details
                                className="timeline-details"
                                open
                            >

                                <summary>
                                    View intelligence data
                                </summary>


                                <pre>
                                    {
                                        JSON.stringify(
                                            intelligence.data
                                            || {},
                                            null,
                                            2
                                        )
                                    }
                                </pre>

                            </details>

                        )
                        : (

                            <div className="empty-inline">

                                No additional multi-agent
                                intelligence was persisted
                                for this incident.

                            </div>
                        )
                    }

                </section>


                {/* ===============================================
                    EXPLANATION
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Decision Explanation
                            </h3>


                            <p>
                                Explainability information
                                associated with the selected
                                Digital Twin plan.
                            </p>

                        </div>

                    </div>


                    {
                        explanation
                        && Object.keys(
                            explanation
                        ).length > 0
                        ? (

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

                        )
                        : (

                            <div className="empty-inline">

                                No explanation data available.

                            </div>
                        )
                    }

                </section>

            </div>


            {/* ===================================================
                SOC TICKET + SAFETY
               =================================================== */}

            <div className="incident-detail-grid">

                {/* ===============================================
                    SOC TICKET
                   =============================================== */}

                <section className="detail-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                SOC Ticket
                            </h3>


                            <p>
                                Persistent ticket generated
                                for this incident.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <div>

                            <span>
                                Ticket ID
                            </span>


                            <strong className="mono-text">

                                {
                                    ticket.ticket_id
                                    || "-"
                                }

                            </strong>

                        </div>


                        <div>

                            <span>
                                Priority
                            </span>


                            <strong>
                                {
                                    ticket.priority
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Risk Score
                            </span>


                            <strong>
                                {
                                    formatValue(
                                        ticket.risk_score
                                    )
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Risk Level
                            </span>


                            <strong>
                                {
                                    ticket.risk_level
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Selected Plan
                            </span>


                            <strong>
                                {
                                    ticket.selected_plan
                                    || "-"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Status
                            </span>


                            <div>

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

                            </div>

                        </div>


                        <div>

                            <span>
                                Approval Status
                            </span>


                            <div>

                                <span
                                    className={
                                        statusClass(
                                            ticket.approval_status
                                        )
                                    }
                                >

                                    {
                                        ticket.approval_status
                                        || "-"
                                    }

                                </span>

                            </div>

                        </div>


                        <div>

                            <span>
                                Assigned Analyst
                            </span>


                            <strong>
                                {
                                    ticket.assigned_analyst
                                    || "-"
                                }
                            </strong>

                        </div>

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
                                Response execution safeguards
                                for the current environment.
                            </p>

                        </div>

                    </div>


                    <div className="detail-list">

                        <div>

                            <span>
                                Simulation Mode
                            </span>


                            <strong>
                                {
                                    safety.simulation_mode
                                    ? "ENABLED"
                                    : "DISABLED"
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Real Endpoint Modified
                            </span>


                            <strong className="safe-disabled">

                                {
                                    safety
                                        .real_endpoint_modified
                                    ? "YES"
                                    : "NO"
                                }

                            </strong>

                        </div>


                        <div>

                            <span>
                                Real Response Executed
                            </span>


                            <strong className="safe-disabled">

                                {
                                    safety
                                        .real_response_executed
                                    ? "YES"
                                    : "NO"
                                }

                            </strong>

                        </div>


                        <div>

                            <span>
                                Response Action Count
                            </span>


                            <strong>
                                {
                                    response.action_count
                                    ?? actions.length
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Approved Actions
                            </span>


                            <strong>
                                {
                                    response
                                        .approval_counts
                                        ?.APPROVED
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Pending Actions
                            </span>


                            <strong>
                                {
                                    response
                                        .approval_counts
                                        ?.PENDING
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div>

                            <span>
                                Ready Actions
                            </span>


                            <strong>
                                {
                                    response
                                        .execution_counts
                                        ?.READY
                                    ?? 0
                                }
                            </strong>

                        </div>

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
                            Policy-controlled response
                            actions generated for this
                            incident.
                        </p>

                    </div>


                    <div className="timeline-count">

                        {actions.length}
                        {" "}
                        actions

                    </div>

                </div>


                {
                    actions.length === 0
                    ? (

                        <div className="empty-inline">

                            No response actions available.

                        </div>

                    )
                    : (

                        <div
                            className="
                                table-container
                                response-table-wrap
                            "
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
                                        ))
                                    }

                                </tbody>

                            </table>

                        </div>
                    )
                }

            </section>


            {/* ===================================================
                DIGITAL TWIN MODEL NOTE
               =================================================== */}

            <div className="digital-twin-note">

                <strong>
                    Interpretation:
                </strong>

                {" "}

                Risk scores, residual-risk values and
                Digital Twin plan scores shown here
                are deterministic heuristic
                decision-support values used by the
                SENTINEL-X prototype. They should not
                be interpreted as calibrated
                probabilities.

            </div>

        </div>
    );
}


export default IncidentDetail;