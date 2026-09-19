import {
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";

import {
    searchTickets,
    approveCase,
    rejectCase,
} from "../api/sentinelApi";


function Approvals() {

    const navigate =
        useNavigate();


    const [
        tickets,
        setTickets,
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
        busyIncident,
        setBusyIncident,
    ] = useState("");


    const [
        analyst,
        setAnalyst,
    ] = useState(
        "SOC Analyst"
    );


    const [
        message,
        setMessage,
    ] = useState("");


    // ============================================================
    // LOAD PENDING APPROVALS
    // ============================================================

    const loadApprovals = async () => {

        try {

            setLoading(true);


            const data =
                await searchTickets({
                    approval_status:
                        "PENDING",
                });


            const pendingTickets =
                data?.tickets || [];


            setTickets(
                pendingTickets
            );


            setError("");

        } catch (err) {

            console.error(
                "Approval queue loading failed:",
                err
            );


            setError(
                "Unable to load approval queue."
            );

        } finally {

            setLoading(false);
        }
    };


    useEffect(() => {

        loadApprovals();

    }, []);


    // ============================================================
    // APPROVE
    // ============================================================

    const handleApprove = async (
        incidentId
    ) => {

        if (!analyst.trim()) {

            setMessage(
                "Enter the analyst name first."
            );

            return;
        }


        const confirmed =
            window.confirm(
                `Approve simulated response actions for ${incidentId}?`
            );


        if (!confirmed) {
            return;
        }


        try {

            setBusyIncident(
                incidentId
            );


            setMessage("");


            await approveCase(
                incidentId,
                analyst.trim(),
                "Approved from SENTINEL-X SOC UI"
            );


            setMessage(
                `Incident ${incidentId} approved successfully.`
            );


            await loadApprovals();

        } catch (err) {

            console.error(
                "Approval failed:",
                err
            );


            setMessage(
                `Approval failed for ${incidentId}.`
            );

        } finally {

            setBusyIncident("");
        }
    };


    // ============================================================
    // REJECT
    // ============================================================

    const handleReject = async (
        incidentId
    ) => {

        if (!analyst.trim()) {

            setMessage(
                "Enter the analyst name first."
            );

            return;
        }


        const reason =
            window.prompt(
                "Enter rejection reason:"
            );


        if (
            reason === null
        ) {
            return;
        }


        if (
            !reason.trim()
        ) {

            setMessage(
                "A rejection reason is required."
            );

            return;
        }


        try {

            setBusyIncident(
                incidentId
            );


            setMessage("");


            await rejectCase(
                incidentId,
                analyst.trim(),
                reason.trim()
            );


            setMessage(
                `Incident ${incidentId} rejected successfully.`
            );


            await loadApprovals();

        } catch (err) {

            console.error(
                "Rejection failed:",
                err
            );


            setMessage(
                `Rejection failed for ${incidentId}.`
            );

        } finally {

            setBusyIncident("");
        }
    };


    // ============================================================
    // PRIORITY STYLE
    // ============================================================

    const priorityClass = (
        value
    ) => {

        const priority =
            String(
                value || ""
            ).toUpperCase();


        if (priority === "P1") {
            return "badge critical";
        }


        if (priority === "P2") {
            return "badge high";
        }


        if (priority === "P3") {
            return "badge medium";
        }


        if (priority === "P4") {
            return "badge low";
        }


        return "badge neutral";
    };


    return (

        <div>

            <div className="page-heading">

                <div>

                    <h2>
                        Analyst Approval Queue
                    </h2>


                    <p>
                        Review Digital Twin response
                        recommendations before
                        simulated execution readiness.
                    </p>

                </div>


                <div className="incident-count">

                    {tickets.length}
                    {" "}
                    pending

                </div>

            </div>


            {/* ===================================================
                SAFETY WARNING
               =================================================== */}

            <div className="approval-safety-banner">

                <strong>
                    Simulation Mode
                </strong>


                <span>
                    Approval changes the workflow
                    state only. Real endpoint response
                    execution remains disabled.
                </span>

            </div>


            {/* ===================================================
                ANALYST NAME
               =================================================== */}

            <section className="approval-analyst-panel">

                <div>

                    <label>
                        Analyst Name
                    </label>


                    <input
                        type="text"
                        value={
                            analyst
                        }
                        onChange={
                            (event) =>
                                setAnalyst(
                                    event.target.value
                                )
                        }
                        placeholder="Enter analyst name"
                    />

                </div>


                <button
                    className="secondary-button"
                    onClick={
                        loadApprovals
                    }
                >
                    Refresh Queue
                </button>

            </section>


            {
                message
                && (

                <div className="approval-message">

                    {message}

                </div>
            )}


            {
                loading
                && (

                <div className="message-card">

                    Loading approval queue...

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
                && tickets.length === 0
                && (

                <div className="message-card">

                    <h3>
                        Approval queue is clear
                    </h3>


                    <p>
                        No SOC tickets currently require
                        analyst approval.
                    </p>

                </div>
            )}


            {/* ===================================================
                APPROVAL CARDS
               =================================================== */}

            <div className="approval-grid">

                {
                    !loading
                    && !error
                    && tickets.map(
                        (
                            ticket,
                            index
                        ) => {

                        const incidentId =
                            ticket.incident_id;


                        const busy =
                            busyIncident
                            === incidentId;


                        return (

                            <article
                                className="approval-card"
                                key={
                                    ticket.ticket_id
                                    || index
                                }
                            >

                                <div className="approval-card-header">

                                    <div>

                                        <span className="approval-label">
                                            INCIDENT
                                        </span>


                                        <h3>
                                            {incidentId}
                                        </h3>

                                    </div>


                                    <span
                                        className={
                                            priorityClass(
                                                ticket.priority
                                            )
                                        }
                                    >

                                        {
                                            ticket.priority
                                            || "-"
                                        }

                                    </span>

                                </div>


                                <div className="approval-metrics">

                                    <div>

                                        <span>
                                            Risk Score
                                        </span>

                                        <strong>
                                            {
                                                ticket.risk_score
                                                ?? "-"
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
                                            Residual Risk
                                        </span>

                                        <strong>
                                            {
                                                ticket
                                                    .predicted_residual_risk
                                                ?? "-"
                                            }
                                        </strong>

                                    </div>


                                    <div>

                                        <span>
                                            Impact
                                        </span>

                                        <strong>
                                            {
                                                ticket
                                                    .operational_impact
                                                || "-"
                                            }
                                        </strong>

                                    </div>

                                </div>


                                <div className="approval-plan">

                                    <span>
                                        Selected Digital Twin Plan
                                    </span>


                                    <strong>
                                        {
                                            ticket.selected_plan
                                            || "-"
                                        }
                                    </strong>

                                </div>


                                {
                                    ticket.explanation
                                    && (

                                    <div className="approval-explanation">

                                        {
                                            typeof ticket.explanation
                                            === "string"
                                                ? ticket.explanation
                                                : JSON.stringify(
                                                    ticket.explanation
                                                )
                                        }

                                    </div>
                                )}


                                <div className="approval-card-actions">

                                    <button
                                        className="secondary-button"
                                        disabled={
                                            busy
                                        }
                                        onClick={
                                            () =>
                                                navigate(
                                                    `/incidents/${incidentId}`
                                                )
                                        }
                                    >
                                        Investigate
                                    </button>


                                    <button
                                        className="reject-button"
                                        disabled={
                                            busy
                                        }
                                        onClick={
                                            () =>
                                                handleReject(
                                                    incidentId
                                                )
                                        }
                                    >
                                        Reject
                                    </button>


                                    <button
                                        className="approve-button"
                                        disabled={
                                            busy
                                        }
                                        onClick={
                                            () =>
                                                handleApprove(
                                                    incidentId
                                                )
                                        }
                                    >

                                        {
                                            busy
                                                ? "Processing..."
                                                : "Approve"
                                        }

                                    </button>

                                </div>

                            </article>
                        );
                    })
                }

            </div>

        </div>
    );
}


export default Approvals;