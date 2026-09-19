import {
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";

import {
    searchActions,
} from "../api/sentinelApi";


function ResponseActions() {

    const navigate =
        useNavigate();


    const [
        actions,
        setActions,
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
        actionType,
        setActionType,
    ] = useState("");


    const [
        approvalStatus,
        setApprovalStatus,
    ] = useState("");


    const [
        executionStatus,
        setExecutionStatus,
    ] = useState("");


    const [
        riskLevel,
        setRiskLevel,
    ] = useState("");


    const [
        incidentId,
        setIncidentId,
    ] = useState("");


    // ============================================================
    // LOAD ACTIONS
    // ============================================================

    const loadActions = async () => {

        try {

            setLoading(true);


            const filters = {};


            if (actionType) {
                filters.action_type =
                    actionType;
            }


            if (approvalStatus) {
                filters.approval_status =
                    approvalStatus;
            }


            if (executionStatus) {
                filters.execution_status =
                    executionStatus;
            }


            if (riskLevel) {
                filters.risk_level =
                    riskLevel;
            }


            if (incidentId.trim()) {
                filters.incident_id =
                    incidentId.trim();
            }


            const data =
                await searchActions(
                    filters
                );


            setActions(
                data?.actions || []
            );


            setError("");

        } catch (err) {

            console.error(
                "Response action loading failed:",
                err
            );


            setError(
                "Unable to load response actions."
            );

        } finally {

            setLoading(false);
        }
    };


    // ============================================================
    // INITIAL LOAD
    // ============================================================

    useEffect(() => {

        loadActions();

    }, []);


    // ============================================================
    // CLEAR FILTERS
    // ============================================================

    const clearFilters = () => {

        setActionType("");
        setApprovalStatus("");
        setExecutionStatus("");
        setRiskLevel("");
        setIncidentId("");


        setTimeout(
            loadActions,
            0
        );
    };


    // ============================================================
    // HELPERS
    // ============================================================

    const riskClass = (
        value
    ) => {

        const risk =
            String(
                value || ""
            ).toUpperCase();


        if (
            risk === "CRITICAL"
        ) {
            return "badge critical";
        }


        if (
            risk === "HIGH"
        ) {
            return "badge high";
        }


        if (
            risk === "MEDIUM"
        ) {
            return "badge medium";
        }


        if (
            risk === "LOW"
            || risk === "INFO"
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
            || status === "READY"
            || status === "SUCCESS"
        ) {
            return "badge low";
        }


        if (
            status === "FAILED"
            || status === "REJECTED"
            || status === "CANCELLED"
        ) {
            return "badge critical";
        }


        if (
            status === "PENDING"
            || status === "EXECUTING"
        ) {
            return "badge high";
        }


        return "badge neutral";
    };


    const policyClass = (
        value
    ) => {

        const policy =
            String(
                value || ""
            ).toUpperCase();


        if (
            policy === "ALLOW"
            || policy === "APPROVED"
        ) {
            return "badge low";
        }


        if (
            policy === "DENY"
            || policy === "BLOCK"
        ) {
            return "badge critical";
        }


        return "badge neutral";
    };


    const formatTarget = (
        target
    ) => {

        if (!target) {
            return "-";
        }


        if (
            typeof target
            === "string"
        ) {
            return target;
        }


        try {

            const entries =
                Object.entries(
                    target
                );


            if (
                entries.length === 0
            ) {
                return "-";
            }


            return entries
                .map(
                    ([key, value]) =>
                        `${key}: ${value}`
                )
                .join(" | ");

        } catch {

            return String(target);
        }
    };


    // ============================================================
    // PAGE
    // ============================================================

    return (

        <div>

            <div className="page-heading">

                <div>

                    <h2>
                        Response Actions
                    </h2>


                    <p>
                        Policy-controlled simulated
                        response actions generated by
                        SENTINEL-X.
                    </p>

                </div>


                <div className="incident-count">

                    {actions.length}
                    {" "}
                    actions

                </div>

            </div>


            {/* ===================================================
                SAFETY BANNER
               =================================================== */}

            <div className="approval-safety-banner">

                <strong>
                    Simulation Mode
                </strong>


                <span>
                    These actions represent
                    decision-support and simulated
                    response workflow states.
                    Real endpoint response execution
                    is disabled.
                </span>

            </div>


            {/* ===================================================
                FILTERS
               =================================================== */}

            <section className="filter-panel">

                <div className="filter-group">

                    <label>
                        Incident ID
                    </label>


                    <input
                        type="text"
                        placeholder="INC-..."
                        value={
                            incidentId
                        }
                        onChange={
                            (event) =>
                                setIncidentId(
                                    event.target.value
                                )
                        }
                    />

                </div>


                <div className="filter-group">

                    <label>
                        Action Type
                    </label>


                    <select
                        value={
                            actionType
                        }
                        onChange={
                            (event) =>
                                setActionType(
                                    event.target.value
                                )
                        }
                    >

                        <option value="">
                            All
                        </option>

                        <option value="MONITOR_INCIDENT">
                            Monitor Incident
                        </option>

                        <option value="INVESTIGATE_INCIDENT">
                            Investigate Incident
                        </option>

                        <option value="QUARANTINE_FILE">
                            Quarantine File
                        </option>

                        <option value="TERMINATE_PROCESS">
                            Terminate Process
                        </option>

                        <option value="BLOCK_NETWORK">
                            Block Network
                        </option>

                        <option value="REMEDIATE_PERSISTENCE">
                            Remediate Persistence
                        </option>

                        <option value="ISOLATE_ENDPOINT">
                            Isolate Endpoint
                        </option>

                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Approval
                    </label>


                    <select
                        value={
                            approvalStatus
                        }
                        onChange={
                            (event) =>
                                setApprovalStatus(
                                    event.target.value
                                )
                        }
                    >

                        <option value="">
                            All
                        </option>

                        <option value="PENDING">
                            Pending
                        </option>

                        <option value="APPROVED">
                            Approved
                        </option>

                        <option value="REJECTED">
                            Rejected
                        </option>

                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Execution
                    </label>


                    <select
                        value={
                            executionStatus
                        }
                        onChange={
                            (event) =>
                                setExecutionStatus(
                                    event.target.value
                                )
                        }
                    >

                        <option value="">
                            All
                        </option>

                        <option value="NOT_EXECUTED">
                            Not Executed
                        </option>

                        <option value="READY">
                            Ready
                        </option>

                        <option value="EXECUTING">
                            Executing
                        </option>

                        <option value="SUCCESS">
                            Success
                        </option>

                        <option value="FAILED">
                            Failed
                        </option>

                        <option value="CANCELLED">
                            Cancelled
                        </option>

                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Risk Level
                    </label>


                    <select
                        value={
                            riskLevel
                        }
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

                        <option value="INFO">
                            Info
                        </option>

                    </select>

                </div>


                <div className="filter-actions">

                    <button
                        className="primary-button"
                        onClick={
                            loadActions
                        }
                    >
                        Apply Filters
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


            {/* ===================================================
                LOADING / ERROR
               =================================================== */}

            {
                loading
                && (

                <div className="message-card">

                    Loading response actions...

                </div>
            )}


            {
                error
                && (

                <div className="message-card error">

                    {error}

                </div>
            )}


            {
                !loading
                && !error
                && actions.length === 0
                && (

                <div className="message-card">

                    No response actions match
                    the selected filters.

                </div>
            )}


            {/* ===================================================
                ACTION TABLE
               =================================================== */}

            {
                !loading
                && !error
                && actions.length > 0
                && (

                <div className="table-container">

                    <table className="soc-table response-actions-table">

                        <thead>

                            <tr>

                                <th>
                                    Action ID
                                </th>

                                <th>
                                    Incident
                                </th>

                                <th>
                                    Action Type
                                </th>

                                <th>
                                    Target
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
                                    Policy
                                </th>

                                <th>
                                    Requested By
                                </th>

                                <th>
                                    Action
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
                                            action.action_id
                                            || index
                                        }
                                    >

                                        <td className="mono-text action-id-cell">

                                            {
                                                action.action_id
                                                || "-"
                                            }

                                        </td>


                                        <td className="incident-id-cell">

                                            {
                                                action.incident_id
                                                || "-"
                                            }

                                        </td>


                                        <td>

                                            <strong className="action-type-text">

                                                {
                                                    action.action_type
                                                    || "-"
                                                }

                                            </strong>

                                        </td>


                                        <td>

                                            <div
                                                className="response-target"
                                                title={
                                                    formatTarget(
                                                        action.target
                                                    )
                                                }
                                            >

                                                {
                                                    formatTarget(
                                                        action.target
                                                    )
                                                }

                                            </div>

                                        </td>


                                        <td>

                                            <span
                                                className={
                                                    riskClass(
                                                        action.risk_level
                                                    )
                                                }
                                            >

                                                {
                                                    action.risk_level
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

                                            <span
                                                className={
                                                    policyClass(
                                                        action
                                                            .policy_decision
                                                    )
                                                }
                                            >

                                                {
                                                    action
                                                        .policy_decision
                                                    || "UNKNOWN"
                                                }

                                            </span>

                                        </td>


                                        <td>

                                            {
                                                action.requested_by
                                                || "-"
                                            }

                                        </td>


                                        <td>

                                            <button
                                                className="table-action-button"
                                                onClick={
                                                    () =>
                                                        navigate(
                                                            `/incidents/${action.incident_id}`
                                                        )
                                                }
                                            >
                                                View Incident
                                            </button>

                                        </td>

                                    </tr>
                                ))
                            }

                        </tbody>

                    </table>

                </div>
            )}

        </div>
    );
}


export default ResponseActions;