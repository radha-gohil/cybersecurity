import {
    useCallback,
    useEffect,
    useState,
} from "react";


import {
    getSecurityRuntime,
} from "../api/sentinelApi";


// ================================================================
// SENTINEL-X SYSTEM HEALTH
//
// Displays real runtime state from:
//
// GET /api/v1/security/runtime
//
// No hard-coded collector state.
// ================================================================


const REFRESH_INTERVAL_MS = 5000;


// ================================================================
// HELPERS
// ================================================================

function safeText(
    value,
    fallback = "—"
) {

    if (
        value === undefined
        ||
        value === null
        ||
        value === ""
    ) {

        return fallback;
    }


    return String(
        value
    );
}


function safeNumber(
    value,
    fallback = 0
) {

    const number =
        Number(
            value
        );


    if (
        Number.isFinite(
            number
        )
    ) {

        return number;
    }


    return fallback;
}


function yesNo(
    value
) {

    return value
        ? "YES"
        : "NO";
}


function statusClass(
    value
) {

    const status =
        String(
            value || ""
        ).toUpperCase();


    if (
        status === "HEALTHY"
        ||
        status === "ACTIVE"
        ||
        status === "PASS"
        ||
        status === "PRIMARY"
        ||
        status === "PRODUCTION_PRIMARY"
    ) {

        return (
            "health-badge healthy"
        );
    }


    return (
        "health-badge unhealthy"
    );
}


function formatDate(
    value
) {

    if (!value) {

        return "—";
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


    return (
        date.toLocaleString()
    );
}


function formatScore(
    value
) {

    const number =
        Number(
            value
        );


    if (
        !Number.isFinite(
            number
        )
    ) {

        return "—";
    }


    return (
        number.toFixed(
            2
        )
    );
}


// ================================================================
// SUMMARY CARD
// ================================================================

function SummaryCard({
    title,
    value,
    subtitle,
}) {

    return (

        <div className="dashboard-panel">

            <div className="panel-heading">

                <div>

                    <p>
                        {title}
                    </p>

                    <h2>
                        {value}
                    </h2>

                    {
                        subtitle
                        &&
                        (
                            <p>
                                {subtitle}
                            </p>
                        )
                    }

                </div>

            </div>

        </div>
    );
}


// ================================================================
// DETAIL ROW
// ================================================================

function DetailRow({
    label,
    value,
}) {

    return (

        <div className="system-row">

            <span>
                {label}
            </span>

            <strong>
                {safeText(
                    value
                )}
            </strong>

        </div>
    );
}


// ================================================================
// COLLECTOR CARD
// ================================================================

function CollectorCard({
    name,
    collector,
}) {

    const healthy =
        Boolean(
            collector?.healthy
        );


    return (

        <div className="dashboard-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        {name}
                    </h3>

                    <p>
                        Endpoint telemetry collector
                    </p>

                </div>


                <div
                    className={
                        statusClass(
                            healthy
                                ? "HEALTHY"
                                : "DEGRADED"
                        )
                    }
                >
                    {
                        healthy
                            ? "ACTIVE"
                            : safeText(
                                collector?.status,
                                "UNKNOWN"
                            )
                    }
                </div>

            </div>


            <div className="system-list">

                <DetailRow
                    label="Thread Alive"
                    value={
                        yesNo(
                            collector
                                ?.thread_alive
                        )
                    }
                />


                <DetailRow
                    label="Heartbeat Fresh"
                    value={
                        yesNo(
                            collector
                                ?.fresh
                        )
                    }
                />


                <DetailRow
                    label="Heartbeat Age"
                    value={
                        collector
                            ?.heartbeat_age_seconds
                        !== null
                        &&
                        collector
                            ?.heartbeat_age_seconds
                        !== undefined
                            ? `${
                                safeNumber(
                                    collector
                                        ?.heartbeat_age_seconds
                                ).toFixed(
                                    1
                                )
                            } s`
                            : "—"
                    }
                />


                <DetailRow
                    label="Last Seen"
                    value={
                        formatDate(
                            collector
                                ?.last_seen
                        )
                    }
                />


                <DetailRow
                    label="Error"
                    value={
                        collector?.error
                        ||
                        "None"
                    }
                />

            </div>

        </div>
    );
}


// ================================================================
// SYSTEM HEALTH PAGE
// ================================================================

export default function SystemHealth() {

    const [
        runtime,
        setRuntime,
    ] = useState(
        null
    );


    const [
        loading,
        setLoading,
    ] = useState(
        true
    );


    const [
        refreshing,
        setRefreshing,
    ] = useState(
        false
    );


    const [
        error,
        setError,
    ] = useState(
        ""
    );


    const [
        lastRefresh,
        setLastRefresh,
    ] = useState(
        null
    );


    // ============================================================
    // LOAD
    // ============================================================

    const loadRuntime =
        useCallback(
            async (
                initial = false
            ) => {

                try {

                    if (initial) {

                        setLoading(
                            true
                        );

                    } else {

                        setRefreshing(
                            true
                        );
                    }


                    const data =
                        await getSecurityRuntime();


                    setRuntime(
                        data || {}
                    );


                    setLastRefresh(
                        new Date()
                    );


                    setError(
                        ""
                    );


                } catch (err) {

                    console.error(
                        "Security runtime loading failed:",
                        err
                    );


                    setError(
                        err?.message
                        ||
                        "Unable to load SENTINEL-X runtime status."
                    );


                } finally {

                    setLoading(
                        false
                    );


                    setRefreshing(
                        false
                    );
                }
            },

            []
        );


    // ============================================================
    // INITIAL LOAD + AUTO REFRESH
    // ============================================================

    useEffect(
        () => {

            loadRuntime(
                true
            );


            const timer =
                setInterval(
                    () => {

                        loadRuntime(
                            false
                        );

                    },

                    REFRESH_INTERVAL_MS
                );


            return () => {

                clearInterval(
                    timer
                );
            };

        },

        [
            loadRuntime
        ]
    );


    // ============================================================
    // INITIAL LOADING
    // ============================================================

    if (
        loading
        &&
        !runtime
    ) {

        return (

            <div className="message-card">

                Loading SENTINEL-X
                production runtime...

            </div>
        );
    }


    // ============================================================
    // DATA
    // ============================================================

    const collectors =
        runtime
            ?.collectors
            ?.collectors
        || {};


    const temporal =
        runtime
            ?.temporal_ai
        || {};


    const fusion =
        runtime
            ?.fusion_v3
        || {};


    const latest =
        fusion
            ?.latest
        || {};


    const checks =
        runtime
            ?.checks
        || {};


    const scores =
        latest
            ?.scores
        || {};


    const categories =
        latest
            ?.categories
        || {};


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
                        System Health
                    </h2>


                    <p>
                        Live SENTINEL-X endpoint,
                        Temporal-AI and Fusion-v3
                        production runtime state.
                    </p>

                </div>


                <div>

                    <div
                        className={
                            statusClass(
                                runtime?.status
                            )
                        }
                    >
                        {
                            runtime?.status
                            ||
                            "UNKNOWN"
                        }
                    </div>


                    <button
                        type="button"
                        className="secondary-button"
                        onClick={
                            () => loadRuntime(
                                false
                            )
                        }
                        disabled={
                            refreshing
                        }
                        style={{
                            marginTop:
                                "10px",
                        }}
                    >
                        {
                            refreshing
                                ? "Refreshing..."
                                : "Refresh"
                        }
                    </button>

                </div>

            </div>


            {/* ===================================================
                ERROR
               =================================================== */}

            {
                error
                &&
                (
                    <div className="message-card error">

                        <strong>
                            Runtime refresh failed
                        </strong>

                        <p>
                            {error}
                        </p>

                    </div>
                )
            }


            {/* ===================================================
                PRODUCTION MODE
               =================================================== */}

            <div className="approval-safety-banner">

                <strong>
                    PROCESS DETECTION MODE
                </strong>


                <span>

                    Fusion v3 is the primary
                    process-threat decision engine.
                    Fusion v2 remains available as
                    the rollback/reference engine.

                    {" "}

                    Real response execution remains
                    disabled.

                </span>

            </div>


            {/* ===================================================
                TOP SUMMARY
               =================================================== */}

            <div className="stats-grid">

                <SummaryCard
                    title="Runtime"
                    value={
                        runtime?.status
                        ||
                        "UNKNOWN"
                    }
                    subtitle="Overall security runtime"
                />


                <SummaryCard
                    title="Primary Engine"
                    value="Fusion v3"
                    subtitle={
                        runtime
                            ?.operating_mode
                        ||
                        "UNKNOWN"
                    }
                />


                <SummaryCard
                    title="Temporal AI"
                    value={
                        temporal
                            ?.model_version
                        ||
                        "UNKNOWN"
                    }
                    subtitle={
                        temporal?.healthy
                            ? "Configuration healthy"
                            : "Configuration review"
                    }
                />


                <SummaryCard
                    title="Collectors"
                    value={
                        `${
                            safeNumber(
                                runtime
                                    ?.collectors
                                    ?.healthy_count
                            )
                        }/${
                            safeNumber(
                                runtime
                                    ?.collectors
                                    ?.expected_count
                            )
                        }`
                    }
                    subtitle="Healthy endpoint collectors"
                />


                <SummaryCard
                    title="Fusion v3 Results"
                    value={
                        safeNumber(
                            fusion
                                ?.total_persisted_results
                        )
                    }
                    subtitle="Persisted decisions"
                />


                <SummaryCard
                    title="V3 Alert Results"
                    value={
                        safeNumber(
                            fusion
                                ?.alert_results
                        )
                    }
                    subtitle="Fusion-v3 alert candidates"
                />

            </div>


            {/* ===================================================
                READINESS CHECKS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Production Runtime Checks
                        </h3>

                        <p>
                            Backend-derived readiness
                            state.
                        </p>

                    </div>

                </div>


                <div className="system-list">

                    <DetailRow
                        label="Collector Runtime"
                        value={
                            checks.collectors
                                ? "PASS"
                                : "REVIEW"
                        }
                    />


                    <DetailRow
                        label="Temporal Transformer v2"
                        value={
                            checks.temporal_v2
                                ? "PASS"
                                : "REVIEW"
                        }
                    />


                    <DetailRow
                        label="Fusion v3 Primary Runtime"
                        value={
                            checks.fusion_v3_primary
                                ? "PASS"
                                : "REVIEW"
                        }
                    />


                    <DetailRow
                        label="Runtime Phase"
                        value={
                            runtime
                                ?.runtime_phase
                        }
                    />


                    <DetailRow
                        label="Last API Refresh"
                        value={
                            lastRefresh
                                ? lastRefresh
                                    .toLocaleTimeString()
                                : "—"
                        }
                    />

                </div>

            </section>


            {/* ===================================================
                COLLECTORS
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Endpoint Collectors
                        </h3>

                        <p>
                            Live collector state from
                            the heartbeat database.
                        </p>

                    </div>


                    <div
                        className={
                            statusClass(
                                runtime
                                    ?.collectors
                                    ?.all_healthy
                                    ? "HEALTHY"
                                    : "DEGRADED"
                            )
                        }
                    >
                        {
                            runtime
                                ?.collectors
                                ?.all_healthy
                                ? "ALL ACTIVE"
                                : "REVIEW"
                        }
                    </div>

                </div>


                <div className="dashboard-grid">

                    <CollectorCard
                        name="Process Collector"
                        collector={
                            collectors.process
                        }
                    />


                    <CollectorCard
                        name="File Collector"
                        collector={
                            collectors.file
                        }
                    />


                    <CollectorCard
                        name="Network Collector"
                        collector={
                            collectors.network
                        }
                    />


                    <CollectorCard
                        name="Registry Collector"
                        collector={
                            collectors.registry
                        }
                    />

                </div>

            </section>


            {/* ===================================================
                FUSION
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Fusion Decision Runtime
                        </h3>

                        <p>
                            Current primary and rollback
                            process-threat decision
                            engines.
                        </p>

                    </div>


                    <div
                        className={
                            statusClass(
                                fusion
                                    ?.primary_runtime_seen
                                    ? "PRIMARY"
                                    : "DEGRADED"
                            )
                        }
                    >
                        {
                            fusion
                                ?.primary_runtime_seen
                                ? "PRIMARY"
                                : "NOT SEEN"
                        }
                    </div>

                </div>


                <div className="dashboard-grid">

                    <div className="dashboard-panel">

                        <div className="system-list">

                            <DetailRow
                                label="Primary Engine"
                                value={
                                    fusion
                                        ?.primary_engine
                                }
                            />


                            <DetailRow
                                label="Version"
                                value={
                                    fusion
                                        ?.primary_version
                                }
                            />


                            <DetailRow
                                label="Mode"
                                value={
                                    fusion
                                        ?.operating_mode
                                }
                            />


                            <DetailRow
                                label="Promoted"
                                value={
                                    yesNo(
                                        fusion
                                            ?.promoted_to_primary
                                    )
                                }
                            />

                        </div>

                    </div>


                    <div className="dashboard-panel">

                        <div className="system-list">

                            <DetailRow
                                label="Rollback Engine"
                                value={
                                    fusion
                                        ?.rollback_engine
                                }
                            />


                            <DetailRow
                                label="Rollback Available"
                                value={
                                    yesNo(
                                        fusion
                                            ?.rollback_available
                                    )
                                }
                            />


                            <DetailRow
                                label="Recent Primary Rows"
                                value={
                                    fusion
                                        ?.recent_primary_results
                                }
                            />


                            <DetailRow
                                label="Four-Category Rows"
                                value={
                                    fusion
                                        ?.four_category_primary_results
                                }
                            />

                        </div>

                    </div>

                </div>

            </section>


            {/* ===================================================
                TEMPORAL AI
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Temporal AI
                        </h3>

                        <p>
                            Self-supervised process
                            sequence anomaly model.
                        </p>

                    </div>


                    <div
                        className={
                            statusClass(
                                temporal?.healthy
                                    ? "HEALTHY"
                                    : "DEGRADED"
                            )
                        }
                    >
                        {
                            temporal?.healthy
                                ? "HEALTHY"
                                : "REVIEW"
                        }
                    </div>

                </div>


                <div className="dashboard-grid">

                    <div className="dashboard-panel">

                        <div className="system-list">

                            <DetailRow
                                label="Model"
                                value={
                                    temporal
                                        ?.model_name
                                }
                            />


                            <DetailRow
                                label="Model Version"
                                value={
                                    temporal
                                        ?.model_version
                                }
                            />


                            <DetailRow
                                label="Predictor"
                                value={
                                    temporal
                                        ?.predictor_version
                                }
                            />


                            <DetailRow
                                label="Calibration"
                                value={
                                    temporal
                                        ?.calibration_version
                                }
                            />

                        </div>

                    </div>


                    <div className="dashboard-panel">

                        <div className="system-list">

                            <DetailRow
                                label="Sequence Length"
                                value={
                                    temporal
                                        ?.sequence_length
                                }
                            />


                            <DetailRow
                                label="Feature Count"
                                value={
                                    temporal
                                        ?.feature_count
                                }
                            />


                            <DetailRow
                                label="Embedding Dimension"
                                value={
                                    temporal
                                        ?.representation_dimension
                                }
                            />


                            <DetailRow
                                label="Removed Feature"
                                value={
                                    temporal
                                        ?.removed_feature
                                }
                            />

                        </div>

                    </div>

                </div>

            </section>


            {/* ===================================================
                LATEST FUSION RESULT
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Latest Fusion-v3 Decision
                        </h3>

                        <p>
                            Most recent persisted
                            process-level Fusion-v3
                            result.
                        </p>

                    </div>


                    <div
                        className={
                            statusClass(
                                latest?.severity
                            )
                        }
                    >
                        {
                            latest?.severity
                            ||
                            "NO DATA"
                        }
                    </div>

                </div>


                {
                    fusion?.latest
                    ? (

                        <>

                            <div className="dashboard-grid">

                                <div className="dashboard-panel">

                                    <div className="system-list">

                                        <DetailRow
                                            label="Process"
                                            value={
                                                latest
                                                    ?.process_name
                                            }
                                        />


                                        <DetailRow
                                            label="PID"
                                            value={
                                                latest
                                                    ?.pid
                                            }
                                        />


                                        <DetailRow
                                            label="Fusion Score"
                                            value={
                                                formatScore(
                                                    latest
                                                        ?.fusion_score
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Severity"
                                            value={
                                                latest
                                                    ?.severity
                                            }
                                        />


                                        <DetailRow
                                            label="Should Alert"
                                            value={
                                                yesNo(
                                                    latest
                                                        ?.should_alert
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Evidence Confidence"
                                            value={
                                                latest
                                                    ?.evidence_confidence
                                            }
                                        />

                                    </div>

                                </div>


                                <div className="dashboard-panel">

                                    <div className="system-list">

                                        <DetailRow
                                            label="Rules"
                                            value={
                                                formatScore(
                                                    scores
                                                        ?.rules
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Statistical"
                                            value={
                                                formatScore(
                                                    scores
                                                        ?.statistical
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Behavioral AI"
                                            value={
                                                formatScore(
                                                    scores
                                                        ?.behavioral_ai_consensus
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Temporal AI"
                                            value={
                                                formatScore(
                                                    scores
                                                        ?.temporal_ai
                                                )
                                            }
                                        />

                                    </div>

                                </div>

                            </div>


                            <div
                                className="dashboard-grid"
                                style={{
                                    marginTop:
                                        "16px",
                                }}
                            >

                                <div className="dashboard-panel">

                                    <div className="system-list">

                                        <DetailRow
                                            label="Rule Available"
                                            value={
                                                yesNo(
                                                    categories
                                                        ?.rules
                                                        ?.available
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Statistical Available"
                                            value={
                                                yesNo(
                                                    categories
                                                        ?.statistical
                                                        ?.available
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Behavioral AI Available"
                                            value={
                                                yesNo(
                                                    categories
                                                        ?.behavioral_ai
                                                        ?.available
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Temporal AI Available"
                                            value={
                                                yesNo(
                                                    categories
                                                        ?.temporal_ai
                                                        ?.available
                                                )
                                            }
                                        />

                                    </div>

                                </div>


                                <div className="dashboard-panel">

                                    <div className="system-list">

                                        <DetailRow
                                            label="Mode"
                                            value={
                                                latest
                                                    ?.operating_mode
                                            }
                                        />


                                        <DetailRow
                                            label="Created"
                                            value={
                                                formatDate(
                                                    latest
                                                        ?.created_at
                                                )
                                            }
                                        />


                                        <DetailRow
                                            label="Active Categories"
                                            value={
                                                Array.isArray(
                                                    latest
                                                        ?.active_categories
                                                )
                                                    ? (
                                                        latest
                                                            .active_categories
                                                            .join(
                                                                ", "
                                                            )
                                                        ||
                                                        "None"
                                                    )
                                                    : "None"
                                            }
                                        />


                                        <DetailRow
                                            label="Strong Categories"
                                            value={
                                                Array.isArray(
                                                    latest
                                                        ?.strong_categories
                                                )
                                                    ? (
                                                        latest
                                                            .strong_categories
                                                            .join(
                                                                ", "
                                                            )
                                                        ||
                                                        "None"
                                                    )
                                                    : "None"
                                            }
                                        />

                                    </div>

                                </div>

                            </div>

                        </>

                    )
                    : (

                        <div className="empty-inline">

                            No production Fusion-v3
                            decision has been persisted
                            yet.

                            Start the SENTINEL-X agent
                            and allow process telemetry
                            to run.

                        </div>
                    )
                }

            </section>


            {/* ===================================================
                SAFETY
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Response Safety
                        </h3>

                        <p>
                            Decision promotion does not
                            enable real endpoint
                            remediation.
                        </p>

                    </div>

                </div>


                <div className="system-list">

                    <DetailRow
                        label="Simulation Mode"
                        value={
                            yesNo(
                                runtime
                                    ?.simulation_mode
                            )
                        }
                    />


                    <DetailRow
                        label="Real Response Execution"
                        value={
                            runtime
                                ?.real_response_execution
                                ? "ENABLED"
                                : "DISABLED"
                        }
                    />


                    <DetailRow
                        label="Primary Decision"
                        value="Fusion v3"
                    />


                    <DetailRow
                        label="Rollback"
                        value="Fusion v2"
                    />

                </div>

            </section>

        </div>
    );
}