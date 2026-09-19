import {
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";

import {
    searchIncidents,
} from "../api/sentinelApi";


function Incidents() {
    const navigate = useNavigate();

    const [
        incidents,
        setIncidents,
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
        riskLevel,
        setRiskLevel,
    ] = useState("");

    const [
        status,
        setStatus,
    ] = useState("");

    const [
        minRisk,
        setMinRisk,
    ] = useState("");


    const loadIncidents = async () => {
        try {
            setLoading(true);

            const filters = {};

            if (riskLevel) {
                filters.risk_level =
                    riskLevel;
            }

            if (status) {
                filters.status =
                    status;
            }

            if (minRisk !== "") {
                filters.min_risk =
                    Number(minRisk);
            }

            const data =
                await searchIncidents(
                    filters
                );

            setIncidents(
                data?.incidents || []
            );

            setError("");

        } catch (err) {
            console.error(
                "Incident loading failed:",
                err
            );

            setError(
                "Unable to load incidents."
            );

        } finally {
            setLoading(false);
        }
    };


    useEffect(() => {
        loadIncidents();
    }, []);


    const applyFilters = () => {
        loadIncidents();
    };


    const clearFilters = () => {
        setRiskLevel("");
        setStatus("");
        setMinRisk("");

        setTimeout(
            () => {
                loadIncidents();
            },
            0
        );
    };


    const getRiskClass = (
        risk
    ) => {
        const value =
            String(
                risk || ""
            ).toUpperCase();

        if (value === "CRITICAL") {
            return "badge critical";
        }

        if (value === "HIGH") {
            return "badge high";
        }

        if (value === "MEDIUM") {
            return "badge medium";
        }

        if (value === "LOW") {
            return "badge low";
        }

        return "badge neutral";
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


    return (
        <div>

            <div className="page-heading">

                <div>
                    <h2>
                        Incidents
                    </h2>

                    <p>
                        Search and investigate
                        persistent SENTINEL-X
                        security incidents.
                    </p>
                </div>

                <div className="incident-count">
                    {incidents.length}
                    {" "}
                    incidents
                </div>

            </div>


            <section className="filter-panel">

                <div className="filter-group">

                    <label>
                        Risk Level
                    </label>

                    <select
                        value={riskLevel}
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
                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Case Status
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

                        <option value="AWAITING_ANALYST_REVIEW">
                            Awaiting Review
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
                    </select>

                </div>


                <div className="filter-group">

                    <label>
                        Minimum Risk
                    </label>

                    <input
                        type="number"
                        min="0"
                        max="100"
                        placeholder="0"
                        value={minRisk}
                        onChange={
                            (event) =>
                                setMinRisk(
                                    event.target.value
                                )
                        }
                    />

                </div>


                <div className="filter-actions">

                    <button
                        className="primary-button"
                        onClick={applyFilters}
                    >
                        Apply Filters
                    </button>

                    <button
                        className="secondary-button"
                        onClick={clearFilters}
                    >
                        Clear
                    </button>

                </div>

            </section>


            {loading && (
                <div className="message-card">
                    Loading incidents...
                </div>
            )}


            {error && (
                <div className="message-card error">
                    {error}
                </div>
            )}


            {!loading &&
                !error &&
                incidents.length === 0 && (

                <div className="message-card">
                    No incidents match
                    the selected filters.
                </div>
            )}


            {!loading &&
                !error &&
                incidents.length > 0 && (

                <div className="table-container">

                    <table className="soc-table">

                        <thead>
                            <tr>
                                <th>
                                    Incident ID
                                </th>

                                <th>
                                    Risk Score
                                </th>

                                <th>
                                    Risk Level
                                </th>

                                <th>
                                    Status
                                </th>

                                <th>
                                    Selected Plan
                                </th>

                                <th>
                                    Residual Risk
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

                            {incidents.map(
                                (incident) => {

                                    const incidentId =
                                        incident.incident_id;

                                    return (
                                        <tr
                                            key={
                                                incidentId
                                            }
                                        >

                                            <td className="incident-id-cell">
                                                {incidentId}
                                            </td>


                                            <td>
                                                <strong>
                                                    {
                                                        incident
                                                            .risk_score
                                                        ?? "-"
                                                    }
                                                </strong>
                                            </td>


                                            <td>
                                                <span
                                                    className={
                                                        getRiskClass(
                                                            incident
                                                                .risk_level
                                                        )
                                                    }
                                                >
                                                    {
                                                        incident
                                                            .risk_level
                                                        || "UNKNOWN"
                                                    }
                                                </span>
                                            </td>


                                            <td>
                                                <span className="badge neutral">
                                                    {
                                                        incident
                                                            .case_status
                                                        || incident
                                                            .status
                                                        || "UNKNOWN"
                                                    }
                                                </span>
                                            </td>


                                            <td>
                                                {
                                                    incident
                                                        .selected_plan
                                                    || "-"
                                                }
                                            </td>


                                            <td>
                                                {
                                                    incident
                                                        .predicted_residual_risk
                                                    ?? "-"
                                                }
                                            </td>


                                            <td>
                                                {
                                                    formatDate(
                                                        incident
                                                            .created_at
                                                    )
                                                }
                                            </td>


                                            <td>
                                                <button
                                                    className="table-action-button"
                                                    onClick={
                                                        () =>
                                                            navigate(
                                                                `/incidents/${incidentId}`
                                                            )
                                                    }
                                                >
                                                    View
                                                </button>
                                            </td>

                                        </tr>
                                    );
                                }
                            )}

                        </tbody>

                    </table>

                </div>
            )}

        </div>
    );
}


export default Incidents;