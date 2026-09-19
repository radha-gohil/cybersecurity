import {
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";

import {
    searchTickets,
} from "../api/sentinelApi";


function Tickets() {

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
        priority,
        setPriority,
    ] = useState("");


    const [
        status,
        setStatus,
    ] = useState("");


    const [
        approvalStatus,
        setApprovalStatus,
    ] = useState("");


    // ============================================================
    // LOAD TICKETS
    // ============================================================

    const loadTickets = async () => {

        try {

            setLoading(true);


            const filters = {};


            if (priority) {
                filters.priority =
                    priority;
            }


            if (status) {
                filters.status =
                    status;
            }


            if (approvalStatus) {
                filters.approval_status =
                    approvalStatus;
            }


            const data =
                await searchTickets(
                    filters
                );


            setTickets(
                data?.tickets || []
            );


            setError("");

        } catch (err) {

            console.error(
                "Ticket loading failed:",
                err
            );


            setError(
                "Unable to load SOC tickets."
            );

        } finally {

            setLoading(false);
        }
    };


    useEffect(() => {

        loadTickets();

    }, []);


    // ============================================================
    // HELPERS
    // ============================================================

    const clearFilters = () => {

        setPriority("");
        setStatus("");
        setApprovalStatus("");


        setTimeout(
            loadTickets,
            0
        );
    };


    const formatDate = (
        value
    ) => {

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

            return value;
        }


        return date.toLocaleString();
    };


    const priorityClass = (
        value
    ) => {

        const priorityValue =
            String(
                value || ""
            ).toUpperCase();


        if (
            priorityValue === "P1"
        ) {
            return "badge critical";
        }


        if (
            priorityValue === "P2"
        ) {
            return "badge high";
        }


        if (
            priorityValue === "P3"
        ) {
            return "badge medium";
        }


        if (
            priorityValue === "P4"
        ) {
            return "badge low";
        }


        return "badge neutral";
    };


    const statusClass = (
        value
    ) => {

        const statusValue =
            String(
                value || ""
            ).toUpperCase();


        if (
            statusValue === "APPROVED"
            || statusValue === "RESOLVED"
            || statusValue === "CLOSED"
        ) {
            return "badge low";
        }


        if (
            statusValue === "REJECTED"
        ) {
            return "badge critical";
        }


        if (
            statusValue === "AWAITING_APPROVAL"
            || statusValue === "PENDING"
            || statusValue === "OPEN"
            || statusValue === "IN_REVIEW"
        ) {
            return "badge high";
        }


        return "badge neutral";
    };


    return (

        <div>

            <div className="page-heading">

                <div>

                    <h2>
                        SOC Tickets
                    </h2>

                    <p>
                        Persistent tickets generated
                        from SENTINEL-X incident
                        intelligence and Digital Twin
                        decisions.
                    </p>

                </div>


                <div className="incident-count">

                    {tickets.length}
                    {" "}
                    tickets

                </div>

            </div>


            {/* ===================================================
                FILTERS
               =================================================== */}

            <section className="filter-panel">

                <div className="filter-group">

                    <label>
                        Priority
                    </label>


                    <select
                        value={priority}
                        onChange={
                            (event) =>
                                setPriority(
                                    event.target.value
                                )
                        }
                    >

                        <option value="">
                            All
                        </option>

                        <option value="P1">
                            P1 Critical
                        </option>

                        <option value="P2">
                            P2 High
                        </option>

                        <option value="P3">
                            P3 Medium
                        </option>

                        <option value="P4">
                            P4 Low
                        </option>

                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Ticket Status
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

                        <option value="OPEN">
                            Open
                        </option>

                        <option value="IN_REVIEW">
                            In Review
                        </option>

                        <option value="AWAITING_APPROVAL">
                            Awaiting Approval
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

                        <option value="CLOSED">
                            Closed
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


                <div className="filter-actions">

                    <button
                        className="primary-button"
                        onClick={
                            loadTickets
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
                STATUS
               =================================================== */}

            {
                loading
                && (

                <div className="message-card">

                    Loading SOC tickets...

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

                    No tickets match the
                    selected filters.

                </div>
            )}


            {/* ===================================================
                TABLE
               =================================================== */}

            {
                !loading
                && !error
                && tickets.length > 0
                && (

                <div className="table-container">

                    <table className="soc-table">

                        <thead>

                            <tr>

                                <th>
                                    Ticket ID
                                </th>

                                <th>
                                    Incident
                                </th>

                                <th>
                                    Priority
                                </th>

                                <th>
                                    Risk
                                </th>

                                <th>
                                    Status
                                </th>

                                <th>
                                    Approval
                                </th>

                                <th>
                                    Selected Plan
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

                            {
                                tickets.map(
                                    (
                                        ticket,
                                        index
                                    ) => (

                                    <tr
                                        key={
                                            ticket.ticket_id
                                            || index
                                        }
                                    >

                                        <td className="mono-text">

                                            {
                                                ticket.ticket_id
                                                || "-"
                                            }

                                        </td>


                                        <td className="incident-id-cell">

                                            {
                                                ticket.incident_id
                                                || "-"
                                            }

                                        </td>


                                        <td>

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

                                        </td>


                                        <td>

                                            <strong>
                                                {
                                                    ticket.risk_score
                                                    ?? "-"
                                                }
                                            </strong>

                                        </td>


                                        <td>

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

                                        </td>


                                        <td>

                                            <span
                                                className={
                                                    statusClass(
                                                        ticket
                                                            .approval_status
                                                    )
                                                }
                                            >

                                                {
                                                    ticket
                                                        .approval_status
                                                    || "-"
                                                }

                                            </span>

                                        </td>


                                        <td>

                                            {
                                                ticket.selected_plan
                                                || "-"
                                            }

                                        </td>


                                        <td>

                                            {
                                                formatDate(
                                                    ticket.created_at
                                                )
                                            }

                                        </td>


                                        <td>

                                            <button
                                                className="table-action-button"
                                                onClick={
                                                    () =>
                                                        navigate(
                                                            `/incidents/${ticket.incident_id}`
                                                        )
                                                }
                                            >
                                                Investigate
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


export default Tickets;