import {
    useEffect,
    useState,
} from "react";

import {
    getDashboardSummary,
    getHealth,
} from "../api/sentinelApi";

import StatCard from "../components/StatCard";


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


    const loadDashboard = async () => {
        try {
            setLoading(true);

            const [
                summaryData,
                healthData,
            ] = await Promise.all([
                getDashboardSummary(),
                getHealth(),
            ]);

            setSummary(
                summaryData
            );

            setHealth(
                healthData
            );

            setError("");

        } catch (err) {
            console.error(
                "Dashboard loading failed:",
                err
            );

            setError(
                "Unable to load SENTINEL-X dashboard data."
            );

        } finally {
            setLoading(false);
        }
    };


    useEffect(() => {
        loadDashboard();

        const interval = setInterval(
            loadDashboard,
            10000
        );

        return () => {
            clearInterval(interval);
        };

    }, []);


    if (loading) {
        return (
            <div className="message-card">
                Loading SOC dashboard...
            </div>
        );
    }


    if (error) {
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
                    onClick={loadDashboard}
                >
                    Retry
                </button>
            </div>
        );
    }


    return (
        <div>
            <div className="page-heading">
                <div>
                    <h2>
                        SOC Overview
                    </h2>

                    <p>
                        Persistent SENTINEL-X
                        security operations summary.
                    </p>
                </div>

                <div
                    className={
                        health?.status === "HEALTHY"
                            ? "health-badge healthy"
                            : "health-badge unhealthy"
                    }
                >
                    {health?.status || "UNKNOWN"}
                </div>
            </div>


            <div className="stats-grid">
                <StatCard
                    title="SOC Cases"
                    value={
                        summary
                            ?.persistent_soc_cases
                        ?? 0
                    }
                    subtitle="Persistent incidents"
                />

                <StatCard
                    title="Critical Incidents"
                    value={
                        summary
                            ?.critical_cases
                        ?? 0
                    }
                    subtitle="Critical risk cases"
                />

                <StatCard
                    title="Open Tickets"
                    value={
                        summary
                            ?.open_tickets
                        ?? 0
                    }
                    subtitle="Active SOC tickets"
                />

                <StatCard
                    title="Pending Approvals"
                    value={
                        summary
                            ?.pending_approvals
                        ?? 0
                    }
                    subtitle="Analyst action required"
                />

                <StatCard
                    title="Response Actions"
                    value={
                        summary
                            ?.total_response_actions
                        ?? 0
                    }
                    subtitle="Generated controls"
                />

                <StatCard
                    title="Ready Actions"
                    value={
                        summary
                            ?.ready_response_actions
                        ?? 0
                    }
                    subtitle="Approved for simulation"
                />
            </div>


            <div className="dashboard-grid">

                <section className="dashboard-panel">

                    <div className="panel-heading">
                        <div>
                            <h3>
                                Ticket Priority
                            </h3>

                            <p>
                                Current SOC ticket
                                distribution.
                            </p>
                        </div>
                    </div>


                    <div className="priority-list">

                        <div className="priority-row">

                            <span>
                                P1 Critical
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.priority_counts
                                        ?.P1
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="priority-row">

                            <span>
                                P2 High
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.priority_counts
                                        ?.P2
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="priority-row">

                            <span>
                                P3 Medium
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.priority_counts
                                        ?.P3
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="priority-row">

                            <span>
                                P4 Low
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.priority_counts
                                        ?.P4
                                    ?? 0
                                }
                            </strong>

                        </div>

                    </div>

                </section>


                <section className="dashboard-panel">

                    <div className="panel-heading">
                        <div>
                            <h3>
                                Platform Safety
                            </h3>

                            <p>
                                Current backend operating mode.
                            </p>
                        </div>
                    </div>


                    <div className="system-list">

                        <div className="system-row">

                            <span>
                                Backend
                            </span>

                            <strong>
                                {
                                    health?.status
                                    || "UNKNOWN"
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Simulation Mode
                            </span>

                            <strong>
                                {
                                    health
                                        ?.simulation_mode
                                    ? "ENABLED"
                                    : "DISABLED"
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Persistent Recovery
                            </span>

                            <strong>
                                {
                                    health
                                        ?.persistent_recovery
                                    ? "ENABLED"
                                    : "DISABLED"
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Evidence Persistence
                            </span>

                            <strong>
                                {
                                    health
                                        ?.evidence_persistence
                                    ? "ENABLED"
                                    : "DISABLED"
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Timeline Persistence
                            </span>

                            <strong>
                                {
                                    health
                                        ?.timeline_persistence
                                    ? "ENABLED"
                                    : "DISABLED"
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Real Response
                            </span>

                            <strong
                                className="safe-disabled"
                            >
                                {
                                    health
                                        ?.real_response_execution
                                    ? "ENABLED"
                                    : "DISABLED"
                                }
                            </strong>

                        </div>

                    </div>

                </section>

            </div>


            <div className="dashboard-grid">

                <section className="dashboard-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Ticket Workflow
                            </h3>

                            <p>
                                Approval and lifecycle
                                summary.
                            </p>

                        </div>

                    </div>


                    <div className="system-list">

                        <div className="system-row">

                            <span>
                                Approved Tickets
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.approved_tickets
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Rejected Tickets
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.rejected_tickets
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Pending Actions
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.pending_response_actions
                                    ?? 0
                                }
                            </strong>

                        </div>

                    </div>

                </section>


                <section className="dashboard-panel">

                    <div className="panel-heading">

                        <div>

                            <h3>
                                Risk Summary
                            </h3>

                            <p>
                                Persisted incident
                                risk distribution.
                            </p>

                        </div>

                    </div>


                    <div className="system-list">

                        <div className="system-row">

                            <span>
                                Critical
                            </span>

                            <strong className="risk-critical">
                                {
                                    summary
                                        ?.critical_cases
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                High
                            </span>

                            <strong className="risk-high">
                                {
                                    summary
                                        ?.high_cases
                                    ?? 0
                                }
                            </strong>

                        </div>


                        <div className="system-row">

                            <span>
                                Awaiting Analyst Review
                            </span>

                            <strong>
                                {
                                    summary
                                        ?.pending_soc_cases
                                    ?? 0
                                }
                            </strong>

                        </div>

                    </div>

                </section>

            </div>

        </div>
    );
}


export default Dashboard;