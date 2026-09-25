import {
    useEffect,
    useMemo,
    useState,
} from "react";

import {
    getDashboardSummary,
    getHealth,
} from "../api/sentinelApi";

import StatCard from "../components/StatCard";


// ================================================================
// HELPERS
// ================================================================

function safeNumber(
    value
) {

    const parsed =
        Number(
            value
        );


    return Number.isFinite(
        parsed
    )
        ? parsed
        : 0;
}


function displayName(
    value
) {

    return String(
        value
        || "UNKNOWN"
    )
        .replaceAll(
            "_",
            " "
        );
}


function Dashboard() {

    const [
        summary,
        setSummary,
    ] = useState(null);


    const [
        health,
        setHealth,
    ] = useState(null);


    const [
        loading,
        setLoading,
    ] = useState(true);


    const [
        error,
        setError,
    ] = useState("");


    const [
        lastRefresh,
        setLastRefresh,
    ] = useState(null);


    // ============================================================
    // LOAD DASHBOARD
    // ============================================================

    const loadDashboard =
        async () => {

            try {

                setLoading(
                    true
                );


                const [
                    summaryData,
                    healthData,
                ] = await Promise.all([

                    getDashboardSummary(),

                    getHealth(),

                ]);


                setSummary(
                    summaryData || {}
                );


                setHealth(
                    healthData || {}
                );


                setLastRefresh(
                    new Date()
                );


                setError(
                    ""
                );


            } catch (
                err
            ) {

                console.error(
                    "Dashboard loading failed:",
                    err
                );


                setError(

                    err?.response
                        ?.data
                        ?.detail

                    || err?.message

                    || "Unable to load SENTINEL-X dashboard data."
                );


            } finally {

                setLoading(
                    false
                );
            }
        };


    // ============================================================
    // AUTO REFRESH
    // ============================================================

    useEffect(
        () => {

            loadDashboard();


            const interval =
                setInterval(

                    loadDashboard,

                    15000
                );


            return () => {

                clearInterval(
                    interval
                );
            };

        },
        []
    );


    // ============================================================
    // DISTRIBUTION DATA
    // ============================================================

    const detectionSeverity =
        summary
            ?.detection_severity_counts
        || {};


    const incidentSeverity =
        summary
            ?.incident_severity_counts
        || {};


    const eventCategories =
        summary
            ?.event_category_counts
        || {};


    const detectionEngines =
        summary
            ?.detection_engine_counts
        || {};


    const mitigationStatus =
        summary
            ?.mitigation_status_counts
        || {};


    const priorityCounts =
        summary
            ?.priority_counts
        || {};


    const sortedEngines =
        useMemo(
            () => {

                return Object.entries(
                    detectionEngines
                ).sort(

                    (
                        first,
                        second
                    ) => (

                        safeNumber(
                            second[
                                1
                            ]
                        )

                        - safeNumber(
                            first[
                                1
                            ]
                        )
                    )
                );

            },
            [
                detectionEngines,
            ]
        );


    // ============================================================
    // LOADING
    // ============================================================

    if (
        loading
        && !summary
    ) {

        return (

            <div className="message-card">

                Loading SENTINEL-X dashboard...

            </div>
        );
    }


    // ============================================================
    // HARD ERROR
    // ============================================================

    if (
        error
        && !summary
    ) {

        return (

            <div className="message-card error">

                <h3>
                    Dashboard unavailable
                </h3>


                <p>
                    {error}
                </p>


                <button
                    className="primary-button"
                    onClick={
                        loadDashboard
                    }
                >
                    Retry
                </button>

            </div>
        );
    }


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
                        SENTINEL-X Overview
                    </h2>


                    <p>

                        Endpoint telemetry, detections,
                        correlated incidents and persistent
                        SOC workflow.

                    </p>

                </div>


                <div
                    style={{
                        display:
                            "flex",

                        gap:
                            "10px",

                        alignItems:
                            "center",
                    }}
                >

                    <div
                        className={
                            health?.status
                            === "HEALTHY"

                                ? "health-badge healthy"

                                : "health-badge unhealthy"
                        }
                    >

                        {
                            health?.status
                            || "UNKNOWN"
                        }

                    </div>


                    <button
                        className="secondary-button"
                        onClick={
                            loadDashboard
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

                </div>

            </div>


            {/* ===================================================
                SAFETY
               =================================================== */}

            <div className="approval-safety-banner">

                <strong>
                    Analyst-Supervised Simulation
                </strong>


                <span>

                    Detection, investigation, Digital Twin
                    evaluation and response recommendation
                    are available. Real endpoint response
                    execution remains disabled.

                </span>

            </div>


            {/* ===================================================
                LOAD ERROR
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
                TELEMETRY / DETECTION KPI
               =================================================== */}

            <div className="stats-grid">

                <StatCard
                    title="Security Events"
                    value={
                        safeNumber(
                            summary?.event_count
                        )
                    }
                    subtitle="Persisted endpoint telemetry"
                />


                <StatCard
                    title="Detections"
                    value={
                        safeNumber(
                            summary?.detection_count
                        )
                    }
                    subtitle="Persisted detector outputs"
                />


                <StatCard
                    title="Detected Incidents"
                    value={
                        safeNumber(
                            summary
                                ?.detected_incidents
                        )
                    }
                    subtitle="Correlation incidents"
                />


                <StatCard
                    title="Awaiting Investigation"
                    value={
                        safeNumber(
                            summary
                                ?.awaiting_investigation
                        )
                    }
                    subtitle="Not yet promoted to SOC"
                />


                <StatCard
                    title="Promoted to SOC"
                    value={
                        safeNumber(
                            summary
                                ?.promoted_to_soc
                        )
                    }
                    subtitle="Investigated incidents"
                />


                <StatCard
                    title="SOC Cases"
                    value={
                        safeNumber(
                            summary
                                ?.persistent_soc_cases
                        )
                    }
                    subtitle="Persistent SOC cases"
                />

            </div>


            {/* ===================================================
                SOC KPI
               =================================================== */}

            <div className="stats-grid">

                <StatCard
                    title="Open Tickets"
                    value={
                        safeNumber(
                            summary
                                ?.open_tickets
                        )
                    }
                    subtitle="Active SOC work items"
                />


                <StatCard
                    title="Pending Reviews"
                    value={
                        safeNumber(
                            summary
                                ?.pending_soc_cases
                        )
                    }
                    subtitle="Awaiting analyst review"
                />


                <StatCard
                    title="Pending Approvals"
                    value={
                        safeNumber(
                            summary
                                ?.pending_approvals
                        )
                    }
                    subtitle="Response approval required"
                />


                <StatCard
                    title="Response Actions"
                    value={
                        safeNumber(
                            summary
                                ?.total_response_actions
                        )
                    }
                    subtitle="Generated response controls"
                />


                <StatCard
                    title="Ready Actions"
                    value={
                        safeNumber(
                            summary
                                ?.ready_response_actions
                        )
                    }
                    subtitle="Ready for simulation"
                />


                <StatCard
                    title="Mitigation Verified"
                    value={
                        safeNumber(
                            summary
                                ?.verified_mitigations
                        )
                    }
                    subtitle="Verified simulated outcomes"
                />

            </div>


            {/* ===================================================
                DETECTION SEVERITY
               =================================================== */}

            <div className="dashboard-grid">

                <DashboardPanel
                    title="Detection Severity"
                    subtitle={
                        "Severity distribution across "
                        + "stored detector outputs."
                    }
                >

                    <MetricRow
                        label="Critical"
                        value={
                            detectionSeverity
                                .CRITICAL
                        }
                        className="risk-critical"
                    />


                    <MetricRow
                        label="High"
                        value={
                            detectionSeverity
                                .HIGH
                        }
                        className="risk-high"
                    />


                    <MetricRow
                        label="Medium"
                        value={
                            detectionSeverity
                                .MEDIUM
                        }
                    />


                    <MetricRow
                        label="Low"
                        value={
                            detectionSeverity
                                .LOW
                        }
                    />


                    <MetricRow
                        label="Info"
                        value={
                            detectionSeverity
                                .INFO
                        }
                    />

                </DashboardPanel>


                {/* =================================================
                    CORRELATED INCIDENTS
                   ================================================= */}

                <DashboardPanel
                    title="Correlation Incidents"
                    subtitle={
                        "Severity of incidents created "
                        + "by event correlation."
                    }
                >

                    <MetricRow
                        label="Critical"
                        value={
                            incidentSeverity
                                .CRITICAL
                        }
                        className="risk-critical"
                    />


                    <MetricRow
                        label="High"
                        value={
                            incidentSeverity
                                .HIGH
                        }
                        className="risk-high"
                    />


                    <MetricRow
                        label="Medium"
                        value={
                            incidentSeverity
                                .MEDIUM
                        }
                    />


                    <MetricRow
                        label="Low"
                        value={
                            incidentSeverity
                                .LOW
                        }
                    />


                    <MetricRow
                        label="Info"
                        value={
                            incidentSeverity
                                .INFO
                        }
                    />

                </DashboardPanel>

            </div>


            {/* ===================================================
                EVENT CATEGORIES / ENGINES
               =================================================== */}

            <div className="dashboard-grid">

                <DashboardPanel
                    title="Telemetry Categories"
                    subtitle={
                        "Persisted SecurityEvent "
                        + "distribution."
                    }
                >

                    {
                        Object.keys(
                            eventCategories
                        ).length === 0

                            ? (

                                <EmptyRow
                                    text={
                                        "No telemetry categories."
                                    }
                                />
                            )

                            : (

                                Object.entries(
                                    eventCategories
                                ).map(

                                    (
                                        [
                                            category,
                                            count,
                                        ]
                                    ) => (

                                        <MetricRow

                                            key={
                                                category
                                            }

                                            label={
                                                displayName(
                                                    category
                                                )
                                            }

                                            value={
                                                count
                                            }
                                        />
                                    )
                                )
                            )
                    }

                </DashboardPanel>


                <DashboardPanel
                    title="Detection Engines"
                    subtitle={
                        "Detectors currently represented "
                        + "in persisted results."
                    }
                >

                    {
                        sortedEngines.length === 0

                            ? (

                                <EmptyRow
                                    text={
                                        "No persisted detections."
                                    }
                                />
                            )

                            : (

                                sortedEngines.map(

                                    (
                                        [
                                            engine,
                                            count,
                                        ]
                                    ) => (

                                        <MetricRow

                                            key={
                                                engine
                                            }

                                            label={
                                                displayName(
                                                    engine
                                                )
                                            }

                                            value={
                                                count
                                            }
                                        />
                                    )
                                )
                            )
                    }

                </DashboardPanel>

            </div>


            {/* ===================================================
                TICKETS / MITIGATION
               =================================================== */}

            <div className="dashboard-grid">

                <DashboardPanel
                    title="Ticket Priority"
                    subtitle={
                        "Current persistent SOC "
                        + "ticket distribution."
                    }
                >

                    <MetricRow
                        label="P1 Critical"
                        value={
                            priorityCounts
                                .P1
                        }
                        className="risk-critical"
                    />


                    <MetricRow
                        label="P2 High"
                        value={
                            priorityCounts
                                .P2
                        }
                        className="risk-high"
                    />


                    <MetricRow
                        label="P3 Medium"
                        value={
                            priorityCounts
                                .P3
                        }
                    />


                    <MetricRow
                        label="P4 Low / Info"
                        value={
                            priorityCounts
                                .P4
                        }
                    />

                </DashboardPanel>


                <DashboardPanel
                    title="Mitigation Verification"
                    subtitle={
                        "Simulated mitigation "
                        + "verification state."
                    }
                >

                    <MetricRow
                        label="Verified"
                        value={
                            mitigationStatus
                                .VERIFIED
                        }
                    />


                    <MetricRow
                        label="Partial"
                        value={
                            mitigationStatus
                                .PARTIAL
                        }
                    />


                    <MetricRow
                        label="Failed"
                        value={
                            mitigationStatus
                                .FAILED
                        }
                    />


                    <MetricRow
                        label="Not Verified"
                        value={
                            mitigationStatus
                                .NOT_VERIFIED
                        }
                    />

                </DashboardPanel>

            </div>


            {/* ===================================================
                RESPONSE / SAFETY
               =================================================== */}

            <div className="dashboard-grid">

                <DashboardPanel
                    title="SOC Workflow"
                    subtitle={
                        "Human-in-the-loop response state."
                    }
                >

                    <MetricRow
                        label="Total Tickets"
                        value={
                            summary
                                ?.total_tickets
                        }
                    />


                    <MetricRow
                        label="Approved Tickets"
                        value={
                            summary
                                ?.approved_tickets
                        }
                    />


                    <MetricRow
                        label="Rejected Tickets"
                        value={
                            summary
                                ?.rejected_tickets
                        }
                    />


                    <MetricRow
                        label="Pending Actions"
                        value={
                            summary
                                ?.pending_response_actions
                        }
                    />


                    <MetricRow
                        label="Ready Actions"
                        value={
                            summary
                                ?.ready_response_actions
                        }
                    />

                </DashboardPanel>


                <DashboardPanel
                    title="Platform Safety"
                    subtitle={
                        "Current SENTINEL-X "
                        + "operating mode."
                    }
                >

                    <MetricRow
                        label="Backend"
                        value={
                            health?.status
                            || "UNKNOWN"
                        }
                    />


                    <MetricRow
                        label="Simulation Mode"
                        value={
                            summary
                                ?.simulation_mode

                                ? "ENABLED"

                                : "DISABLED"
                        }
                    />


                    <MetricRow
                        label="Persistent Recovery"
                        value={
                            summary
                                ?.persistent_recovery

                                ? "ENABLED"

                                : "DISABLED"
                        }
                    />


                    <MetricRow
                        label="Collector Runtime"
                        value={
                            summary
                                ?.live_collection_started_by_api

                                ? "STARTED"

                                : "NOT STARTED BY API"
                        }
                    />


                    <MetricRow
                        label="Real Response"
                        value={
                            summary
                                ?.real_response_execution

                                ? "ENABLED"

                                : "DISABLED"
                        }
                        className="safe-disabled"
                    />

                </DashboardPanel>

            </div>


            {/* ===================================================
                FOOTER
               =================================================== */}

            <div className="message-card">

                <strong>
                    Data source:
                </strong>

                {" "}

                {
                    summary?.data_source
                    || "UNKNOWN"
                }

                {" | "}

                <strong>
                    Last refresh:
                </strong>

                {" "}

                {
                    lastRefresh

                        ? lastRefresh
                            .toLocaleTimeString()

                        : "-"
                }

            </div>

        </div>
    );
}


// ================================================================
// DASHBOARD PANEL
// ================================================================

function DashboardPanel({
    title,
    subtitle,
    children,
}) {

    return (

        <section className="dashboard-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        {title}
                    </h3>


                    <p>
                        {subtitle}
                    </p>

                </div>

            </div>


            <div className="system-list">

                {children}

            </div>

        </section>
    );
}


// ================================================================
// METRIC ROW
// ================================================================

function MetricRow({
    label,
    value,
    className = "",
}) {

    return (

        <div className="system-row">

            <span>
                {label}
            </span>


            <strong
                className={
                    className
                }
            >

                {
                    value
                    ?? 0
                }

            </strong>

        </div>
    );
}


// ================================================================
// EMPTY ROW
// ================================================================

function EmptyRow({
    text,
}) {

    return (

        <div className="system-row">

            <span>
                {text}
            </span>


            <strong>
                0
            </strong>

        </div>
    );
}


export default Dashboard;