import {
    useEffect,
    useState,
} from "react";

import {
    getMitigationVerification,
    verifyMitigation,
} from "../../services/socApi";

import "./MitigationVerificationPanel.css";


const EMPTY_STATE = {
    risk_score: "",
    suspicious_event_count: "",
    active_indicator_count: "",
    exposure_score: "",
};


function numberOrZero(value) {

    const parsed =
        Number(value);

    if (
        Number.isNaN(parsed)
    ) {
        return 0;
    }

    return parsed;
}


function formatImprovement(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "-";
    }

    return `${(
        Number(value) * 100
    ).toFixed(1)}%`;
}


function formatMetricName(name) {

    return String(name || "")
        .replaceAll("_", " ")
        .replace(
            /\b\w/g,
            (character) =>
                character.toUpperCase()
        );
}


function statusClass(status) {

    const normalized =
        String(status || "")
            .toUpperCase();

    if (
        normalized ===
        "SIMULATION_VERIFIED"
    ) {
        return "verified";
    }

    if (
        normalized ===
        "SIMULATION_PARTIAL"
    ) {
        return "partial";
    }

    if (
        normalized ===
        "SIMULATION_NO_IMPROVEMENT"
    ) {
        return "failed";
    }

    return "pending";
}


function MitigationVerificationPanel({
    incidentId,
    initialBeforeState = null,
    initialAfterState = null,
    responsePlanId = "",
}) {

    const [
        beforeState,
        setBeforeState,
    ] = useState({
        ...EMPTY_STATE,
        ...(initialBeforeState || {}),
    });


    const [
        afterState,
        setAfterState,
    ] = useState({
        ...EMPTY_STATE,
        ...(initialAfterState || {}),
    });


    const [
        verificationResponse,
        setVerificationResponse,
    ] = useState(null);


    const [
        loading,
        setLoading,
    ] = useState(false);


    const [
        checking,
        setChecking,
    ] = useState(true);


    const [
        error,
        setError,
    ] = useState("");


    // ============================================================
    // LOAD EXISTING VERIFICATION
    // ============================================================

    async function loadVerification() {

        if (!incidentId) {

            setChecking(false);

            return;
        }

        try {

            setChecking(true);

            setError("");


            const result =
                await getMitigationVerification(
                    incidentId
                );


            setVerificationResponse(
                result
            );

        } catch (err) {

            console.error(
                "Unable to load mitigation verification:",
                err
            );


            setError(
                err.message ||
                "Unable to load mitigation verification."
            );

        } finally {

            setChecking(false);

        }
    }


    useEffect(
        () => {

            loadVerification();

        },
        [incidentId]
    );


    // ============================================================
    // UPDATE INPUT
    // ============================================================

    function updateBefore(
        key,
        value
    ) {

        setBeforeState(
            (previous) => ({
                ...previous,
                [key]: value,
            })
        );
    }


    function updateAfter(
        key,
        value
    ) {

        setAfterState(
            (previous) => ({
                ...previous,
                [key]: value,
            })
        );
    }


    // ============================================================
    // RUN VERIFICATION
    // ============================================================

    async function handleVerify() {

        if (!incidentId) {

            setError(
                "Incident ID is missing."
            );

            return;
        }


        try {

            setLoading(true);

            setError("");


            const normalizedBefore = {

                risk_score:
                    numberOrZero(
                        beforeState.risk_score
                    ),

                suspicious_event_count:
                    numberOrZero(
                        beforeState
                            .suspicious_event_count
                    ),

                active_indicator_count:
                    numberOrZero(
                        beforeState
                            .active_indicator_count
                    ),

                exposure_score:
                    numberOrZero(
                        beforeState.exposure_score
                    ),
            };


            const normalizedAfter = {

                risk_score:
                    numberOrZero(
                        afterState.risk_score
                    ),

                suspicious_event_count:
                    numberOrZero(
                        afterState
                            .suspicious_event_count
                    ),

                active_indicator_count:
                    numberOrZero(
                        afterState
                            .active_indicator_count
                    ),

                exposure_score:
                    numberOrZero(
                        afterState.exposure_score
                    ),
            };


            const responseResult = {

                simulation_mode:
                    true,

                plan_id:
                    responsePlanId ||
                    "soc-ui-simulated-plan",

                action:
                    "SIMULATED_CONTAINMENT",
            };


            const result =
                await verifyMitigation(

                    incidentId,

                    normalizedBefore,

                    normalizedAfter,

                    responseResult
                );


            setVerificationResponse(
                result
            );


            await loadVerification();

        } catch (err) {

            console.error(
                "Mitigation verification failed:",
                err
            );


            setError(
                err.message ||
                "Mitigation verification failed."
            );

        } finally {

            setLoading(false);

        }
    }


    // ============================================================
    // RESULT EXTRACTION
    // ============================================================

    const verification =
        verificationResponse
            ?.verification ||
        {};


    const status =
        verificationResponse
            ?.status ||
        verification.status ||
        "NOT_VERIFIED";


    const verified =
        verificationResponse
            ?.verified === true ||
        status !== "NOT_VERIFIED";


    const metrics =
        verification.metrics ||
        {};


    // ============================================================
    // RENDER
    // ============================================================

    return (

        <section
            className="
                detail-panel
                full-width-panel
                mitigation-panel
            "
        >

            <div className="mitigation-header">

                <div>

                    <h3>
                        Mitigation Verification
                    </h3>

                    <p>
                        Compare the modeled security state
                        before and after the simulated
                        response.
                    </p>

                </div>


                <span
                    className={
                        `mitigation-status
                        ${statusClass(status)}`
                    }
                >

                    {status.replaceAll("_", " ")}

                </span>

            </div>


            <div className="mitigation-safety">

                <div>

                    <strong>
                        SIMULATION ONLY
                    </strong>

                    <span>
                        No real endpoint response is
                        executed by this verification.
                    </span>

                </div>


                <span className="safe-indicator">

                    Real Response Execution:
                    &nbsp;
                    DISABLED

                </span>

            </div>


            {
                error
                && (

                    <div className="mitigation-error">

                        {error}

                    </div>

                )
            }


            {
                checking
                    ? (

                        <div className="mitigation-loading">

                            Loading verification state...

                        </div>

                    )
                    : (

                        <>
                            {/* ================================
                                BEFORE / AFTER INPUT
                               ================================ */}

                            <div className="state-comparison">

                                <div className="state-card">

                                    <div className="state-title">

                                        <span>
                                            BEFORE
                                        </span>

                                        Security State

                                    </div>


                                    <MetricInput
                                        label="Risk Score"
                                        value={
                                            beforeState
                                                .risk_score
                                        }
                                        onChange={
                                            (value) =>
                                                updateBefore(
                                                    "risk_score",
                                                    value
                                                )
                                        }
                                    />


                                    <MetricInput
                                        label="Suspicious Events"
                                        value={
                                            beforeState
                                                .suspicious_event_count
                                        }
                                        onChange={
                                            (value) =>
                                                updateBefore(
                                                    "suspicious_event_count",
                                                    value
                                                )
                                        }
                                    />


                                    <MetricInput
                                        label="Active Indicators"
                                        value={
                                            beforeState
                                                .active_indicator_count
                                        }
                                        onChange={
                                            (value) =>
                                                updateBefore(
                                                    "active_indicator_count",
                                                    value
                                                )
                                        }
                                    />


                                    <MetricInput
                                        label="Exposure Score"
                                        value={
                                            beforeState
                                                .exposure_score
                                        }
                                        onChange={
                                            (value) =>
                                                updateBefore(
                                                    "exposure_score",
                                                    value
                                                )
                                        }
                                    />

                                </div>


                                <div className="mitigation-arrow">

                                    →

                                </div>


                                <div className="state-card after">

                                    <div className="state-title">

                                        <span>
                                            AFTER
                                        </span>

                                        Simulated State

                                    </div>


                                    <MetricInput
                                        label="Risk Score"
                                        value={
                                            afterState
                                                .risk_score
                                        }
                                        onChange={
                                            (value) =>
                                                updateAfter(
                                                    "risk_score",
                                                    value
                                                )
                                        }
                                    />


                                    <MetricInput
                                        label="Suspicious Events"
                                        value={
                                            afterState
                                                .suspicious_event_count
                                        }
                                        onChange={
                                            (value) =>
                                                updateAfter(
                                                    "suspicious_event_count",
                                                    value
                                                )
                                        }
                                    />


                                    <MetricInput
                                        label="Active Indicators"
                                        value={
                                            afterState
                                                .active_indicator_count
                                        }
                                        onChange={
                                            (value) =>
                                                updateAfter(
                                                    "active_indicator_count",
                                                    value
                                                )
                                        }
                                    />


                                    <MetricInput
                                        label="Exposure Score"
                                        value={
                                            afterState
                                                .exposure_score
                                        }
                                        onChange={
                                            (value) =>
                                                updateAfter(
                                                    "exposure_score",
                                                    value
                                                )
                                        }
                                    />

                                </div>

                            </div>


                            <div className="verification-action">

                                <button
                                    onClick={
                                        handleVerify
                                    }
                                    disabled={
                                        loading
                                    }
                                >

                                    {
                                        loading
                                            ? "Verifying..."
                                            : verified
                                                ? "Run Verification Again"
                                                : "Verify Simulated Mitigation"
                                    }

                                </button>

                            </div>


                            {/* ================================
                                VERIFICATION RESULT
                               ================================ */}

                            {
                                verified
                                &&
                                Object.keys(
                                    verification
                                ).length > 0
                                && (

                                    <div className="verification-result">

                                        <h4>
                                            Verification Result
                                        </h4>


                                        <div className="verification-summary-grid">

                                            <ResultCard
                                                title="Status"
                                                value={
                                                    status
                                                        .replaceAll(
                                                            "_",
                                                            " "
                                                        )
                                                }
                                            />


                                            <ResultCard
                                                title="Overall Improvement"
                                                value={
                                                    formatImprovement(
                                                        verification
                                                            .overall_improvement
                                                    )
                                                }
                                            />


                                            <ResultCard
                                                title="Residual Risk"
                                                value={
                                                    verification
                                                        .residual_risk ??
                                                    "-"
                                                }
                                            />


                                            <ResultCard
                                                title="Acceptable Risk"
                                                value={
                                                    verification
                                                        .acceptable_residual_risk ??
                                                    "-"
                                                }
                                            />

                                        </div>


                                        {
                                            Object.keys(
                                                metrics
                                            ).length > 0
                                            && (

                                                <div className="metrics-table-wrapper">

                                                    <table className="metrics-table">

                                                        <thead>

                                                            <tr>

                                                                <th>
                                                                    Metric
                                                                </th>

                                                                <th>
                                                                    Before
                                                                </th>

                                                                <th>
                                                                    After
                                                                </th>

                                                                <th>
                                                                    Reduction
                                                                </th>

                                                                <th>
                                                                    Weight
                                                                </th>

                                                            </tr>

                                                        </thead>


                                                        <tbody>

                                                            {
                                                                Object.entries(
                                                                    metrics
                                                                ).map(
                                                                    ([
                                                                        name,
                                                                        metric
                                                                    ]) => (

                                                                        <tr key={name}>

                                                                            <td>
                                                                                {
                                                                                    formatMetricName(
                                                                                        name
                                                                                    )
                                                                                }
                                                                            </td>

                                                                            <td>
                                                                                {
                                                                                    metric
                                                                                        ?.before ??
                                                                                    "-"
                                                                                }
                                                                            </td>

                                                                            <td>
                                                                                {
                                                                                    metric
                                                                                        ?.after ??
                                                                                    "-"
                                                                                }
                                                                            </td>

                                                                            <td>
                                                                                {
                                                                                    formatImprovement(
                                                                                        metric
                                                                                            ?.reduction
                                                                                    )
                                                                                }
                                                                            </td>

                                                                            <td>
                                                                                {
                                                                                    formatImprovement(
                                                                                        metric
                                                                                            ?.weight
                                                                                    )
                                                                                }
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


                                        {
                                            verification
                                                .recommendation
                                            && (

                                                <div className="verification-text">

                                                    <strong>
                                                        Recommendation
                                                    </strong>

                                                    <p>
                                                        {
                                                            verification
                                                                .recommendation
                                                        }
                                                    </p>

                                                </div>

                                            )
                                        }


                                        {
                                            verification
                                                .interpretation
                                            && (

                                                <div className="verification-text interpretation">

                                                    <strong>
                                                        Interpretation
                                                    </strong>

                                                    <p>
                                                        {
                                                            verification
                                                                .interpretation
                                                        }
                                                    </p>

                                                </div>

                                            )
                                        }


                                        <div className="verification-footer">

                                            <span>
                                                Persisted:
                                                {" "}
                                                {
                                                    verificationResponse
                                                        ?.persistent === true ||
                                                    verificationResponse
                                                        ?.persisted === true
                                                        ? "YES"
                                                        : "NO"
                                                }
                                            </span>


                                            <span>
                                                Simulation:
                                                {" "}
                                                {
                                                    verificationResponse
                                                        ?.simulation_mode !== false
                                                        ? "YES"
                                                        : "NO"
                                                }
                                            </span>


                                            <span>
                                                Real Endpoint Modified:
                                                {" "}
                                                {
                                                    verificationResponse
                                                        ?.real_response_executed === true
                                                        ? "YES"
                                                        : "NO"
                                                }
                                            </span>

                                        </div>

                                    </div>

                                )
                            }

                        </>

                    )
            }

        </section>
    );
}


// ============================================================
// METRIC INPUT
// ============================================================

function MetricInput({
    label,
    value,
    onChange,
}) {

    return (

        <div className="metric-input-row">

            <label>
                {label}
            </label>


            <input
                type="number"
                min="0"
                value={value}
                onChange={
                    (event) =>
                        onChange(
                            event.target.value
                        )
                }
            />

        </div>

    );
}


// ============================================================
// RESULT CARD
// ============================================================

function ResultCard({
    title,
    value,
}) {

    return (

        <div className="verification-result-card">

            <span>
                {title}
            </span>

            <strong>
                {value}
            </strong>

        </div>

    );
}


export default MitigationVerificationPanel;