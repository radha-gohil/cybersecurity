import {
    useEffect,
    useState,
} from "react";

import {
    getEndpointOverview,
} from "../api/sentinelApi";


function Endpoint() {

    const [
        endpoint,
        setEndpoint,
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
    // LOAD ENDPOINT DATA
    // ============================================================

    const loadEndpoint = async () => {

        try {

            setLoading(true);


            const data =
                await getEndpointOverview();


            setEndpoint(
                data || {}
            );


            setError("");

        } catch (err) {

            console.error(
                "Endpoint monitoring error:",
                err
            );


            setError(
                "Unable to load endpoint monitoring data."
            );

        } finally {

            setLoading(false);
        }
    };


    // ============================================================
    // INITIAL LOAD
    // ============================================================

    useEffect(() => {

        loadEndpoint();

    }, []);


    // ============================================================
    // HELPERS
    // ============================================================

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


    const formatDetails = (
        value
    ) => {

        if (
            value === undefined
            || value === null
        ) {
            return "-";
        }


        if (
            typeof value
            === "string"
        ) {
            return value;
        }


        try {

            return JSON.stringify(
                value
            );

        } catch {

            return String(value);
        }
    };


    // ============================================================
    // LOADING
    // ============================================================

    if (loading) {

        return (

            <div className="message-card">

                Loading endpoint monitoring...

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
                    Endpoint Monitoring Unavailable
                </h3>


                <p>
                    {error}
                </p>


                <button
                    className="primary-button"
                    onClick={
                        loadEndpoint
                    }
                >
                    Retry
                </button>

            </div>
        );
    }


    const collectors =
        endpoint?.collectors || {};


    const events =
        Array.isArray(
            endpoint?.events
        )
            ? endpoint.events
            : [];


    const detections =
        Array.isArray(
            endpoint?.detections
        )
            ? endpoint.detections
            : [];


    return (

        <div>

            {/* ===================================================
                HEADER
               =================================================== */}

            <div className="page-heading">

                <div>

                    <h2>
                        Endpoint Monitoring
                    </h2>


                    <p>
                        Read-only endpoint telemetry,
                        collector status and security
                        observations.
                    </p>

                </div>


                <button
                    className="secondary-button"
                    onClick={
                        loadEndpoint
                    }
                >
                    Refresh
                </button>

            </div>


            {/* ===================================================
                SAFETY BANNER
               =================================================== */}

            <div className="approval-safety-banner">

                <strong>
                    Observation Mode
                </strong>


                <span>
                    Endpoint telemetry is displayed
                    for monitoring and investigation.
                    Real response execution remains
                    disabled.
                </span>

            </div>


            {/* ===================================================
                SUMMARY
               =================================================== */}

            <div className="endpoint-summary-grid">

                <SummaryCard
                    title="Platform Status"
                    value={
                        endpoint?.status
                        || "UNKNOWN"
                    }
                />


                <SummaryCard
                    title="Security Events"
                    value={
                        endpoint?.event_count
                        ?? events.length
                    }
                />


                <SummaryCard
                    title="Detections"
                    value={
                        endpoint?.detection_count
                        ?? detections.length
                    }
                />


                <SummaryCard
                    title="Real Response"
                    value={
                        endpoint
                            ?.real_response_execution
                            ? "ENABLED"
                            : "DISABLED"
                    }
                />

            </div>


            {/* ===================================================
                COLLECTORS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Telemetry Collectors
                        </h3>


                        <p>
                            Monitoring components
                            configured for endpoint
                            observation.
                        </p>

                    </div>

                </div>


                <div className="collector-grid">

                    <CollectorCard
                        title="Process Collector"
                        status={
                            collectors.process
                            || "UNKNOWN"
                        }
                    />


                    <CollectorCard
                        title="File Collector"
                        status={
                            collectors.file
                            || "UNKNOWN"
                        }
                    />


                    <CollectorCard
                        title="Network Collector"
                        status={
                            collectors.network
                            || "UNKNOWN"
                        }
                    />


                    <CollectorCard
                        title="Registry Collector"
                        status={
                            collectors.registry
                            || "UNKNOWN"
                        }
                    />

                </div>

            </section>


            {/* ===================================================
                EVENTS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Recent Security Events
                        </h3>


                        <p>
                            Latest endpoint observations
                            stored by SENTINEL-X.
                        </p>

                    </div>


                    <span className="timeline-count">

                        {events.length}
                        {" "}
                        events

                    </span>

                </div>


                {
                    events.length === 0
                    ? (

                        <div className="empty-inline">

                            No endpoint events available.

                        </div>

                    )
                    : (

                        <div className="table-container endpoint-table-wrap">

                            <table className="soc-table endpoint-events-table">

                                <thead>

                                    <tr>

                                        <th>
                                            Time
                                        </th>

                                        <th>
                                            Event Type
                                        </th>

                                        <th>
                                            Source
                                        </th>

                                        <th>
                                            Severity
                                        </th>

                                        <th>
                                            Details
                                        </th>

                                    </tr>

                                </thead>


                                <tbody>

                                    {
                                        events.map(
                                            (
                                                event,
                                                index
                                            ) => (

                                            <tr
                                                key={
                                                    event.event_id
                                                    || index
                                                }
                                            >

                                                <td>

                                                    {
                                                        formatDate(
                                                            event.timestamp
                                                            || event.created_at
                                                        )
                                                    }

                                                </td>


                                                <td>

                                                    {
                                                        event.event_type
                                                        || event.type
                                                        || "-"
                                                    }

                                                </td>


                                                <td>

                                                    {
                                                        event.source
                                                        || event.collector
                                                        || "-"
                                                    }

                                                </td>


                                                <td>

                                                    <SeverityBadge
                                                        value={
                                                            event.severity
                                                        }
                                                    />

                                                </td>


                                                <td>

                                                    <div
                                                        className="endpoint-event-details"
                                                        title={
                                                            formatDetails(
                                                                event.details
                                                                || event.data
                                                            )
                                                        }
                                                    >

                                                        {
                                                            formatDetails(
                                                                event.details
                                                                || event.data
                                                            )
                                                        }

                                                    </div>

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
                DETECTIONS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Recent Detections
                        </h3>


                        <p>
                            Detection results generated
                            from endpoint telemetry.
                        </p>

                    </div>


                    <span className="timeline-count">

                        {detections.length}
                        {" "}
                        detections

                    </span>

                </div>


                {
                    detections.length === 0
                    ? (

                        <div className="empty-inline">

                            No detections available.

                        </div>

                    )
                    : (

                        <div className="table-container endpoint-table-wrap">

                            <table className="soc-table endpoint-events-table">

                                <thead>

                                    <tr>

                                        <th>
                                            Time
                                        </th>

                                        <th>
                                            Engine
                                        </th>

                                        <th>
                                            Detection
                                        </th>

                                        <th>
                                            Risk
                                        </th>

                                        <th>
                                            Details
                                        </th>

                                    </tr>

                                </thead>


                                <tbody>

                                    {
                                        detections.map(
                                            (
                                                detection,
                                                index
                                            ) => (

                                            <tr
                                                key={
                                                    detection.detection_id
                                                    || index
                                                }
                                            >

                                                <td>

                                                    {
                                                        formatDate(
                                                            detection.timestamp
                                                            || detection.created_at
                                                        )
                                                    }

                                                </td>


                                                <td>

                                                    {
                                                        detection.engine
                                                        || detection.source
                                                        || "-"
                                                    }

                                                </td>


                                                <td>

                                                    {
                                                        detection.detection_type
                                                        || detection.type
                                                        || "-"
                                                    }

                                                </td>


                                                <td>

                                                    <SeverityBadge
                                                        value={
                                                            detection.risk_level
                                                            || detection.severity
                                                        }
                                                    />

                                                </td>


                                                <td>

                                                    <div
                                                        className="endpoint-event-details"
                                                        title={
                                                            formatDetails(
                                                                detection.details
                                                                || detection.data
                                                            )
                                                        }
                                                    >

                                                        {
                                                            formatDetails(
                                                                detection.details
                                                                || detection.data
                                                            )
                                                        }

                                                    </div>

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

        </div>
    );
}


// ================================================================
// SUMMARY CARD
// ================================================================

function SummaryCard({
    title,
    value,
}) {

    return (

        <div className="endpoint-summary-card">

            <span>
                {title}
            </span>


            <strong>
                {value}
            </strong>

        </div>
    );
}


// ================================================================
// COLLECTOR CARD
// ================================================================

function CollectorCard({
    title,
    status,
}) {

    const normalized =
        String(
            status || ""
        ).toUpperCase();


    const active =
        normalized === "ACTIVE"
        || normalized === "HEALTHY";


    return (

        <div className="collector-card">

            <span>
                {title}
            </span>


            <strong
                className={
                    active
                        ? "collector-status active"
                        : "collector-status inactive"
                }
            >

                {status}

            </strong>

        </div>
    );
}


// ================================================================
// SEVERITY BADGE
// ================================================================

function SeverityBadge({
    value,
}) {

    const severity =
        String(
            value || "INFO"
        ).toUpperCase();


    let className =
        "badge neutral";


    if (
        severity === "CRITICAL"
    ) {

        className =
            "badge critical";

    } else if (
        severity === "HIGH"
    ) {

        className =
            "badge high";

    } else if (
        severity === "MEDIUM"
    ) {

        className =
            "badge medium";

    } else if (
        severity === "LOW"
        || severity === "INFO"
    ) {

        className =
            "badge low";
    }


    return (

        <span className={className}>

            {severity}

        </span>
    );
}


export default Endpoint;