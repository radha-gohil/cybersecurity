import {
    useEffect,
    useState,
} from "react";

import {
    getEndpointOverview,
} from "../api/sentinelApi";


// ================================================================
// GENERAL HELPERS
// ================================================================

function formatDate(
    value
) {

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

        return String(
            value
        );
    }


    return date.toLocaleString();
}


function formatDetails(
    value
) {

    if (
        value === undefined
        || value === null
        || value === ""
    ) {

        return "-";
    }


    if (
        typeof value === "string"
    ) {

        return value;
    }


    if (
        Array.isArray(
            value
        )
    ) {

        return value.length > 0
            ? value.map(
                (item) =>
                    formatDetails(
                        item
                    )
            ).join("; ")
            : "-";
    }


    try {

        return JSON.stringify(
            value
        );

    } catch {

        return String(
            value
        );
    }
}


function hasObjectData(
    value
) {

    return Boolean(

        value

        && typeof value
        === "object"

        && !Array.isArray(
            value
        )

        && Object.keys(
            value
        ).length > 0
    );
}


// ================================================================
// EVENT SUMMARY
// ================================================================

function summarizeEvent(
    event
) {

    const details = [];


    const process =
        hasObjectData(
            event?.process
        )
            ? event.process
            : {};


    const file =
        hasObjectData(
            event?.file
        )
            ? event.file
            : {};


    const network =
        hasObjectData(
            event?.network
        )
            ? event.network
            : {};


    const registry =
        hasObjectData(
            event?.registry
        )
            ? event.registry
            : {};


    const metadata =
        hasObjectData(
            event?.metadata
        )
            ? event.metadata
            : {};


    // ============================================================
    // PROCESS
    // ============================================================

    if (
        Object.keys(
            process
        ).length > 0
    ) {

        const processName =

            process.name

            || process.process_name

            || process.image

            || process.exe

            || "process";


        const pid =

            process.pid

            ?? process.process_id;


        details.push(

            pid !== undefined

                ? `Process: ${processName} (PID ${pid})`

                : `Process: ${processName}`
        );
    }


    // ============================================================
    // FILE
    // ============================================================

    if (
        Object.keys(
            file
        ).length > 0
    ) {

        const path =

            file.path

            || file.file_path

            || file.name;


        if (path) {

            details.push(
                `File: ${path}`
            );
        }
    }


    // ============================================================
    // NETWORK
    // ============================================================

    if (
        Object.keys(
            network
        ).length > 0
    ) {

        const remoteIp =

            network.remote_ip

            || network.destination_ip

            || network.dst_ip;


        const remotePort =

            network.remote_port

            ?? network.destination_port

            ?? network.dst_port;


        const localIp =

            network.local_ip

            || network.source_ip

            || network.src_ip;


        const localPort =

            network.local_port

            ?? network.source_port

            ?? network.src_port;


        if (
            localIp
            || remoteIp
        ) {

            const localSide =

                localIp

                    ? `${localIp}${
                        localPort !== undefined
                            ? `:${localPort}`
                            : ""
                    }`

                    : "local";


            const remoteSide =

                remoteIp

                    ? `${remoteIp}${
                        remotePort !== undefined
                            ? `:${remotePort}`
                            : ""
                    }`

                    : "remote";


            details.push(

                `Network: ${localSide} → ${remoteSide}`
            );
        }
    }


    // ============================================================
    // REGISTRY
    // ============================================================

    if (
        Object.keys(
            registry
        ).length > 0
    ) {

        const registryPath =

            registry.path

            || registry.key_path

            || registry.key

            || registry.registry_path;


        if (
            registryPath
        ) {

            details.push(
                `Registry: ${registryPath}`
            );
        }
    }


    // ============================================================
    // USEFUL METADATA
    // ============================================================

    const usefulMetadataKeys = [

        "user",

        "username",

        "source_ip",

        "result",

        "remote_ip",

        "bytes_sent",

        "collector",

        "auth_detection_count",

        "network_detection_count",

        "phishing_detection_count",

        "exfiltration_detection_count",

        "detection_count",
    ];


    const metadataSummary = [];


    usefulMetadataKeys.forEach(
        (
            key
        ) => {

            if (
                metadata[
                    key
                ] !== undefined

                && metadata[
                    key
                ] !== null

                && metadata[
                    key
                ] !== ""
            ) {

                metadataSummary.push(

                    `${key}: ${
                        formatDetails(
                            metadata[
                                key
                            ]
                        )
                    }`
                );
            }
        }
    );


    if (
        metadataSummary.length > 0
    ) {

        details.push(
            metadataSummary.join(
                ", "
            )
        );
    }


    if (
        details.length === 0

        && Object.keys(
            metadata
        ).length > 0
    ) {

        details.push(

            formatDetails(
                metadata
            )
        );
    }


    return details.length > 0

        ? details.join(
            " | "
        )

        : "-";
}


// ================================================================
// LEGACY DETECTION TYPE
// ================================================================

function getLegacyDetectionTypes(
    detection
) {

    const metadata =
        hasObjectData(
            detection?.metadata
        )
            ? detection.metadata
            : {};


    const types = [];


    Object.entries(
        metadata
    ).forEach(

        (
            [
                key,
                value,
            ]
        ) => {

            const normalizedKey =
                String(
                    key
                ).toLowerCase();


            if (
                !normalizedKey.includes(
                    "detection_type"
                )
            ) {

                return;
            }


            if (
                Array.isArray(
                    value
                )
            ) {

                value.forEach(
                    (
                        item
                    ) => {

                        if (
                            item
                        ) {

                            types.push(
                                String(
                                    item
                                )
                            );
                        }
                    }
                );

            } else if (
                value
            ) {

                types.push(
                    String(
                        value
                    )
                );
            }
        }
    );


    return [
        ...new Set(
            types
        ),
    ];
}


// ================================================================
// DETECTION LABEL
// ================================================================

function getDetectionLabel(
    detection
) {

    const directType =

        detection?.detection_type

        || detection?.threat_type

        || detection?.type;


    if (
        directType

        && String(
            directType
        ).toUpperCase()
        !== "UNKNOWN"
    ) {

        return directType;
    }


    const legacyTypes =
        getLegacyDetectionTypes(
            detection
        );


    if (
        legacyTypes.length > 0
    ) {

        return (
            `Legacy record: ${
                legacyTypes.join(
                    ", "
                )
            }`
        );
    }


    return "Legacy stored detection";
}


// ================================================================
// DETECTION SUMMARY
// ================================================================

function summarizeDetection(
    detection
) {

    const details = [];


    if (
        detection?.risk_score
        !== undefined

        && detection?.risk_score
        !== null
    ) {

        details.push(
            `Risk: ${detection.risk_score}`
        );
    }


    if (
        detection?.confidence
        !== undefined

        && detection?.confidence
        !== null
    ) {

        details.push(
            `Confidence: ${detection.confidence}`
        );
    }


    const reason =
        formatDetails(
            detection?.reason
        );


    if (
        reason !== "-"
    ) {

        details.push(
            `Reason: ${reason}`
        );
    }


    const eventSummary =
        summarizeEvent(
            detection
        );


    if (
        eventSummary !== "-"
    ) {

        details.push(
            eventSummary
        );
    }


    return details.length > 0

        ? details.join(
            " | "
        )

        : "-";
}


// ================================================================
// ENDPOINT COMPONENT
// ================================================================

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
    // LOAD DATA
    // ============================================================

    const loadEndpoint =
        async () => {

            try {

                setLoading(
                    true
                );

                setError(
                    ""
                );


                const data =
                    await getEndpointOverview();


                setEndpoint(
                    data || {}
                );


            } catch (
                err
            ) {

                console.error(
                    "Endpoint monitoring error:",
                    err
                );


                setError(

                    err?.response
                        ?.data
                        ?.detail

                    || err?.message

                    || "Unable to load endpoint monitoring data."
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

            loadEndpoint();

        },
        []
    );


    // ============================================================
    // LOADING
    // ============================================================

    if (
        loading
    ) {

        return (

            <div className="message-card">

                Loading endpoint monitoring...

            </div>
        );
    }


    // ============================================================
    // ERROR
    // ============================================================

    if (
        error
    ) {

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


    // ============================================================
    // DATA
    // ============================================================

    const collectors =
        endpoint?.collectors
        || {};


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


    const eventCategoryCounts =
        endpoint
            ?.event_category_counts
        || {};


    const eventSeverityCounts =
        endpoint
            ?.event_severity_counts
        || {};


    const detectionSeverityCounts =
        endpoint
            ?.detection_severity_counts
        || {};


    const detectionEngineCounts =
        endpoint
            ?.detection_engine_counts
        || {};


    const detectionTypeCounts =
        endpoint
            ?.detection_type_counts
        || {};


    // ============================================================
    // RENDER
    // ============================================================

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
                        Read-only view of persisted SENTINEL-X
                        endpoint telemetry and detection data.
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
                SAFETY
               =================================================== */}

            <div className="approval-safety-banner">

                <strong>
                    Observation Mode
                </strong>

                <span>

                    Stored endpoint telemetry and detections
                    are read from SQLite. Real response
                    execution is disabled.

                </span>

            </div>


            {/* ===================================================
                COLLECTOR RUNTIME
               =================================================== */}

            <div className="message-card">

                <strong>
                    Collector Runtime:
                </strong>

                {" "}

                {
                    endpoint
                        ?.live_collection_started_by_api

                        ? "Started by API"

                        : "Not started by the FastAPI process"
                }

                {" — "}

                {
                    endpoint?.collector_note

                    || (
                        "Collector runtime heartbeat "
                        + "is not currently tracked."
                    )
                }

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
                    title="Correlated Incidents"
                    value={
                        endpoint?.incident_count
                        ?? 0
                    }
                />


                <SummaryCard
                    title="Awaiting Investigation"
                    value={
                        endpoint
                            ?.awaiting_investigation_count
                        ?? 0
                    }
                />


                <SummaryCard
                    title="Promoted to SOC"
                    value={
                        endpoint
                            ?.promoted_incident_count
                        ?? 0
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


                <SummaryCard
                    title="Data Source"
                    value={
                        endpoint?.data_source
                        || "UNKNOWN"
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

                            CONFIGURED means the collector
                            module is available. It does not
                            mean that collector is currently
                            running.

                        </p>

                    </div>

                </div>


                <div className="collector-grid">

                    {
                        Object.entries(
                            collectors
                        ).map(

                            (
                                [
                                    name,
                                    collectorStatus,
                                ]
                            ) => (

                                <CollectorCard

                                    key={
                                        name
                                    }

                                    title={
                                        `${name.toUpperCase()} Collector`
                                    }

                                    status={
                                        collectorStatus
                                    }
                                />
                            )
                        )
                    }

                </div>

            </section>


            {/* ===================================================
                EVENT CATEGORY COUNTS
               =================================================== */}

            <CountSection

                title="Event Categories"

                description={
                    "Stored telemetry grouped by "
                    + "SENTINEL-X event category."
                }

                data={
                    eventCategoryCounts
                }
            />


            {/* ===================================================
                EVENT SEVERITIES
               =================================================== */}

            <CountSection

                title="Event Severity Distribution"

                description={
                    "Severity distribution across "
                    + "persisted endpoint events."
                }

                data={
                    eventSeverityCounts
                }

                severity
            />


            {/* ===================================================
                DETECTION SEVERITIES
               =================================================== */}

            <CountSection

                title="Detection Severity Distribution"

                description={
                    "Severity distribution across "
                    + "persisted detection records."
                }

                data={
                    detectionSeverityCounts
                }

                severity
            />


            {/* ===================================================
                DETECTION ENGINES
               =================================================== */}

            <CountSection

                title="Detection Engines"

                description={
                    "Persisted detections grouped by "
                    + "the detector or engine that "
                    + "produced them."
                }

                data={
                    detectionEngineCounts
                }
            />


            {/* ===================================================
                DETECTION TYPES
               =================================================== */}

            <CountSection

                title="Detection Types"

                description={
                    "Persisted detection types. Older "
                    + "rows may appear as UNKNOWN because "
                    + "the previous storage writer did not "
                    + "normalize detection_type into "
                    + "threat_type."
                }

                data={
                    detectionTypeCounts
                }
            />


            {/* ===================================================
                RECENT EVENTS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Recent Security Events
                        </h3>

                        <p>

                            Latest endpoint observations
                            read directly from the persisted
                            endpoint database.

                        </p>

                    </div>


                    <span className="timeline-count">

                        {events.length}

                        {" "}

                        displayed

                    </span>

                </div>


                {
                    events.length === 0

                        ? (

                            <div className="empty-inline">

                                No endpoint events
                                are stored yet.

                            </div>
                        )

                        : (

                            <div
                                className={
                                    "table-container "
                                    + "endpoint-table-wrap"
                                }
                            >

                                <table
                                    className={
                                        "soc-table "
                                        + "endpoint-events-table"
                                    }
                                >

                                    <thead>

                                        <tr>

                                            <th>
                                                Time
                                            </th>

                                            <th>
                                                Category
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
                                                ) => {

                                                    const detailText =
                                                        summarizeEvent(
                                                            event
                                                        );


                                                    return (

                                                        <tr
                                                            key={
                                                                event
                                                                    .event_id

                                                                || index
                                                            }
                                                        >

                                                            <td>

                                                                {
                                                                    formatDate(

                                                                        event.timestamp

                                                                        || event
                                                                            .created_at
                                                                    )
                                                                }

                                                            </td>


                                                            <td>

                                                                {
                                                                    event
                                                                        .event_category

                                                                    || "SYSTEM"
                                                                }

                                                            </td>


                                                            <td>

                                                                {
                                                                    event
                                                                        .event_type

                                                                    || "-"
                                                                }

                                                            </td>


                                                            <td>

                                                                {
                                                                    event.source

                                                                    || "-"
                                                                }

                                                            </td>


                                                            <td>

                                                                <SeverityBadge
                                                                    value={
                                                                        event
                                                                            .severity
                                                                    }
                                                                />

                                                            </td>


                                                            <td>

                                                                <div
                                                                    className={
                                                                        "endpoint-event-details"
                                                                    }
                                                                    title={
                                                                        detailText
                                                                    }
                                                                >

                                                                    {
                                                                        detailText
                                                                    }

                                                                </div>

                                                            </td>

                                                        </tr>
                                                    );
                                                }
                                            )
                                        }

                                    </tbody>

                                </table>

                            </div>
                        )
                }

            </section>


            {/* ===================================================
                RECENT DETECTIONS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Recent Detections
                        </h3>

                        <p>

                            Detection records joined back
                            to their originating endpoint
                            telemetry events.

                        </p>

                    </div>


                    <span className="timeline-count">

                        {detections.length}

                        {" "}

                        displayed

                    </span>

                </div>


                {
                    detections.length === 0

                        ? (

                            <div className="empty-inline">

                                No detection records
                                are stored yet.

                            </div>
                        )

                        : (

                            <div
                                className={
                                    "table-container "
                                    + "endpoint-table-wrap"
                                }
                            >

                                <table
                                    className={
                                        "soc-table "
                                        + "endpoint-events-table"
                                    }
                                >

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
                                                Severity
                                            </th>

                                            <th>
                                                Risk Score
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
                                                ) => {

                                                    const detailText =
                                                        summarizeDetection(
                                                            detection
                                                        );


                                                    return (

                                                        <tr
                                                            key={
                                                                detection
                                                                    .detection_id

                                                                || (
                                                                    `${detection.event_id}-${index}`
                                                                )
                                                            }
                                                        >

                                                            <td>

                                                                {
                                                                    formatDate(

                                                                        detection
                                                                            .event_timestamp

                                                                        || detection
                                                                            .created_at
                                                                    )
                                                                }

                                                            </td>


                                                            <td>

                                                                {
                                                                    detection
                                                                        .engine

                                                                    || "unknown"
                                                                }

                                                            </td>


                                                            <td>

                                                                {
                                                                    getDetectionLabel(
                                                                        detection
                                                                    )
                                                                }

                                                            </td>


                                                            <td>

                                                                <SeverityBadge
                                                                    value={
                                                                        detection
                                                                            .severity
                                                                    }
                                                                />

                                                            </td>


                                                            <td>

                                                                {
                                                                    detection
                                                                        .risk_score

                                                                    ?? "-"
                                                                }

                                                            </td>


                                                            <td>

                                                                <div
                                                                    className={
                                                                        "endpoint-event-details"
                                                                    }
                                                                    title={
                                                                        detailText
                                                                    }
                                                                >

                                                                    {
                                                                        detailText
                                                                    }

                                                                </div>

                                                            </td>

                                                        </tr>
                                                    );
                                                }
                                            )
                                        }

                                    </tbody>

                                </table>

                            </div>
                        )
                }

            </section>


            <div className="message-card">

                Last API snapshot:

                {" "}

                {
                    formatDate(
                        endpoint?.timestamp
                    )
                }

            </div>

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
            status
            || "UNKNOWN"
        ).toUpperCase();


    const active =

        normalized === "ACTIVE"

        || normalized === "HEALTHY";


    const className =

        active

            ? "collector-status active"

            : "collector-status inactive";


    return (

        <div className="collector-card">

            <span>
                {title}
            </span>

            <strong
                className={
                    className
                }
            >
                {
                    status
                    || "UNKNOWN"
                }
            </strong>

        </div>
    );
}


// ================================================================
// COUNT SECTION
// ================================================================

function CountSection({
    title,
    description,
    data,
    severity = false,
}) {

    const entries =
        Object.entries(
            data || {}
        ).sort(

            (
                first,
                second
            ) => (

                Number(
                    second[
                        1
                    ]
                )

                - Number(
                    first[
                        1
                    ]
                )
            )
        );


    return (

        <section className="detail-panel full-width-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        {title}
                    </h3>

                    <p>
                        {description}
                    </p>

                </div>

            </div>


            {
                entries.length === 0

                    ? (

                        <div className="empty-inline">

                            No stored data available.

                        </div>
                    )

                    : (

                        <div className="table-container">

                            <table className="soc-table">

                                <thead>

                                    <tr>

                                        <th>
                                            Name
                                        </th>

                                        <th>
                                            Count
                                        </th>

                                    </tr>

                                </thead>


                                <tbody>

                                    {
                                        entries.map(

                                            (
                                                [
                                                    name,
                                                    count,
                                                ]
                                            ) => (

                                                <tr
                                                    key={
                                                        name
                                                    }
                                                >

                                                    <td>

                                                        {
                                                            severity

                                                                ? (

                                                                    <SeverityBadge
                                                                        value={
                                                                            name
                                                                        }
                                                                    />
                                                                )

                                                                : name
                                                        }

                                                    </td>


                                                    <td>
                                                        {count}
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
            value
            || "INFO"
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

        <span
            className={
                className
            }
        >

            {severity}

        </span>
    );
}


export default Endpoint;