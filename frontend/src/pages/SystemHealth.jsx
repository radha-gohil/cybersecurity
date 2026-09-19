import {
    useEffect,
    useState,
} from "react";

import {
    getHealth,
    getIntegritySummary,
} from "../api/sentinelApi";


function SystemHealth() {

    const [
        health,
        setHealth,
    ] = useState(null);


    const [
        integrity,
        setIntegrity,
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
    // LOAD SYSTEM HEALTH
    // ============================================================

    const loadSystemHealth = async () => {

        try {

            setLoading(true);


            const [
                healthData,
                integrityData,
            ] = await Promise.all([
                getHealth(),
                getIntegritySummary(),
            ]);


            setHealth(
                healthData
            );


            setIntegrity(
                integrityData
            );


            setError("");

        } catch (err) {

            console.error(
                "System health loading failed:",
                err
            );


            setError(
                "Unable to load system health information."
            );

        } finally {

            setLoading(false);
        }
    };


    // ============================================================
    // AUTO REFRESH
    // ============================================================

    useEffect(() => {

        loadSystemHealth();


        const interval =
            setInterval(
                loadSystemHealth,
                15000
            );


        return () => {

            clearInterval(
                interval
            );
        };

    }, []);


    // ============================================================
    // HELPERS
    // ============================================================

    const booleanStatus = (
        value
    ) => {

        return value
            ? "ENABLED"
            : "DISABLED";
    };


    const statusClass = (
        value
    ) => {

        const status =
            String(
                value || ""
            ).toUpperCase();


        if (
            status === "HEALTHY"
            || status === "ENABLED"
            || status === "PASS"
            || status === "PASSED"
            || status === "OK"
        ) {

            return "system-status healthy";
        }


        if (
            status === "DISABLED"
            || status === "UNKNOWN"
        ) {

            return "system-status neutral";
        }


        return "system-status unhealthy";
    };


    const integrityStatus =
        integrity?.status
        || integrity?.overall_status
        || (
            integrity?.healthy === true
                ? "HEALTHY"
                : integrity?.healthy === false
                ? "ISSUES_FOUND"
                : "UNKNOWN"
        );


    const issues =
        integrity?.issues
        || integrity?.errors
        || integrity?.problems
        || [];


    const warnings =
        integrity?.warnings
        || [];


    // ============================================================
    // LOADING
    // ============================================================

    if (loading) {

        return (

            <div className="message-card">

                Loading SENTINEL-X
                system health...

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
                    System health unavailable
                </h3>


                <p>
                    {error}
                </p>


                <button
                    className="primary-button"
                    onClick={
                        loadSystemHealth
                    }
                >
                    Retry
                </button>

            </div>
        );
    }


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
                        Backend services, persistence,
                        integrity and safety status.
                    </p>

                </div>


                <button
                    className="secondary-button"
                    onClick={
                        loadSystemHealth
                    }
                >
                    Refresh
                </button>

            </div>


            {/* ===================================================
                TOP SUMMARY
               =================================================== */}

            <div className="system-health-summary">

                <HealthSummaryCard
                    title="Backend"
                    value={
                        health?.status
                        || "UNKNOWN"
                    }
                />


                <HealthSummaryCard
                    title="Integrity"
                    value={
                        integrityStatus
                    }
                />


                <HealthSummaryCard
                    title="Simulation"
                    value={
                        booleanStatus(
                            health
                                ?.simulation_mode
                        )
                    }
                />


                <HealthSummaryCard
                    title="Real Response"
                    value={
                        booleanStatus(
                            health
                                ?.real_response_execution
                        )
                    }
                    safe={
                        health
                            ?.real_response_execution
                        === false
                    }
                />

            </div>


            {/* ===================================================
                CORE PLATFORM
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Core Platform Services
                        </h3>


                        <p>
                            Current backend feature
                            availability reported by
                            the API.
                        </p>

                    </div>

                </div>


                <div className="health-service-grid">

                    <ServiceCard
                        title="Backend API"
                        status={
                            health?.status
                            || "UNKNOWN"
                        }
                        description="FastAPI service state"
                    />


                    <ServiceCard
                        title="Persistent Recovery"
                        status={
                            booleanStatus(
                                health
                                    ?.persistent_recovery
                            )
                        }
                        description="SOC case recovery after restart"
                    />


                    <ServiceCard
                        title="Evidence Persistence"
                        status={
                            booleanStatus(
                                health
                                    ?.evidence_persistence
                            )
                        }
                        description="Incident evidence storage"
                    />


                    <ServiceCard
                        title="Timeline Persistence"
                        status={
                            booleanStatus(
                                health
                                    ?.timeline_persistence
                            )
                        }
                        description="Attack timeline storage"
                    />


                    <ServiceCard
                        title="Query Service"
                        status={
                            booleanStatus(
                                health
                                    ?.query_service
                            )
                        }
                        description="Incident, ticket and action search"
                    />


                    <ServiceCard
                        title="Integrity Service"
                        status={
                            booleanStatus(
                                health
                                    ?.integrity_service
                            )
                        }
                        description="Cross-store consistency validation"
                    />

                </div>

            </section>


            {/* ===================================================
                SAFETY
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Safety Configuration
                        </h3>


                        <p>
                            Current response execution
                            restrictions.
                        </p>

                    </div>

                </div>


                <div className="health-detail-list">

                    <div>

                        <span>
                            Simulation Mode
                        </span>


                        <strong
                            className={
                                statusClass(
                                    booleanStatus(
                                        health
                                            ?.simulation_mode
                                    )
                                )
                            }
                        >

                            {
                                booleanStatus(
                                    health
                                        ?.simulation_mode
                                )
                            }

                        </strong>

                    </div>


                    <div>

                        <span>
                            Real Response Execution
                        </span>


                        <strong
                            className={
                                health
                                    ?.real_response_execution
                                ? "system-status unhealthy"
                                : "system-status healthy"
                            }
                        >

                            {
                                booleanStatus(
                                    health
                                        ?.real_response_execution
                                )
                            }

                        </strong>

                    </div>


                    <div>

                        <span>
                            Operating Mode
                        </span>


                        <strong className="system-status healthy">

                            {
                                health
                                    ?.simulation_mode
                                ? "SAFE SIMULATION"
                                : "UNKNOWN"
                            }

                        </strong>

                    </div>

                </div>

            </section>


            {/* ===================================================
                INTEGRITY
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Backend Integrity
                        </h3>


                        <p>
                            Consistency checks across
                            SOC cases, tickets,
                            response actions, evidence
                            and timeline records.
                        </p>

                    </div>


                    <span
                        className={
                            statusClass(
                                integrityStatus
                            )
                        }
                    >

                        {integrityStatus}

                    </span>

                </div>


                <div className="integrity-stats-grid">

                    <IntegrityMetric
                        title="Cases Checked"
                        value={
                            integrity
                                ?.cases_checked
                            ?? integrity
                                ?.incident_count
                            ?? "-"
                        }
                    />


                    <IntegrityMetric
                        title="Tickets Checked"
                        value={
                            integrity
                                ?.tickets_checked
                            ?? "-"
                        }
                    />


                    <IntegrityMetric
                        title="Actions Checked"
                        value={
                            integrity
                                ?.actions_checked
                            ?? "-"
                        }
                    />


                    <IntegrityMetric
                        title="Issues"
                        value={
                            integrity
                                ?.issue_count
                            ?? issues.length
                        }
                    />

                </div>


                {/* ===============================================
                    ISSUES
                   =============================================== */}

                <div className="health-result-section">

                    <h4>
                        Integrity Issues
                    </h4>


                    {
                        issues.length === 0
                        ? (

                            <div className="integrity-success">

                                No integrity issues
                                were reported by the
                                backend check.

                            </div>

                        )
                        : (

                            <div className="integrity-list">

                                {
                                    issues.map(
                                        (
                                            item,
                                            index
                                        ) => (

                                        <div
                                            className="integrity-item issue"
                                            key={
                                                item.id
                                                || index
                                            }
                                        >

                                            {
                                                typeof item
                                                === "string"
                                                    ? item
                                                    : JSON.stringify(
                                                        item,
                                                        null,
                                                        2
                                                    )
                                            }

                                        </div>
                                    ))
                                }

                            </div>
                        )
                    }

                </div>


                {/* ===============================================
                    WARNINGS
                   =============================================== */}

                {
                    warnings.length > 0
                    && (

                    <div className="health-result-section">

                        <h4>
                            Warnings
                        </h4>


                        <div className="integrity-list">

                            {
                                warnings.map(
                                    (
                                        item,
                                        index
                                    ) => (

                                    <div
                                        className="integrity-item warning"
                                        key={
                                            index
                                        }
                                    >

                                        {
                                            typeof item
                                            === "string"
                                                ? item
                                                : JSON.stringify(
                                                    item,
                                                    null,
                                                    2
                                                )
                                        }

                                    </div>
                                ))
                            }

                        </div>

                    </div>
                )}

            </section>


            {/* ===================================================
                RAW HEALTH DATA
               =================================================== */}

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Diagnostic Information
                        </h3>


                        <p>
                            Raw API state for
                            development and debugging.
                        </p>

                    </div>

                </div>


                <details className="health-diagnostic">

                    <summary>
                        View backend health response
                    </summary>


                    <pre>
                        {
                            JSON.stringify(
                                health,
                                null,
                                2
                            )
                        }
                    </pre>

                </details>


                <details className="health-diagnostic">

                    <summary>
                        View integrity response
                    </summary>


                    <pre>
                        {
                            JSON.stringify(
                                integrity,
                                null,
                                2
                            )
                        }
                    </pre>

                </details>

            </section>

        </div>
    );
}


// ================================================================
// SUMMARY CARD
// ================================================================

function HealthSummaryCard({
    title,
    value,
    safe = false,
}) {

    return (

        <div className="health-summary-card">

            <span>
                {title}
            </span>


            <strong
                className={
                    safe
                        ? "safe-value"
                        : ""
                }
            >

                {value}

            </strong>

        </div>
    );
}


// ================================================================
// SERVICE CARD
// ================================================================

function ServiceCard({
    title,
    status,
    description,
}) {

    const normalized =
        String(
            status || ""
        ).toUpperCase();


    const healthy =
        normalized === "HEALTHY"
        || normalized === "ENABLED";


    return (

        <div className="health-service-card">

            <div className="health-service-header">

                <span>
                    {title}
                </span>


                <span
                    className={
                        healthy
                            ? "service-dot healthy"
                            : "service-dot inactive"
                    }
                />

            </div>


            <strong>
                {status}
            </strong>


            <p>
                {description}
            </p>

        </div>
    );
}


// ================================================================
// INTEGRITY METRIC
// ================================================================

function IntegrityMetric({
    title,
    value,
}) {

    return (

        <div className="integrity-metric">

            <span>
                {title}
            </span>


            <strong>
                {value}
            </strong>

        </div>
    );
}


export default SystemHealth;