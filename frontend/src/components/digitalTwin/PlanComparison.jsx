function PlanComparison({
    digitalTwin = {},
}) {
    const plans =
        digitalTwin.candidate_plans || [];

    const selected =
        digitalTwin.selected_plan || {};


    if (plans.length === 0) {
        return (
            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <h3>
                        Digital Twin Plan Comparison
                    </h3>

                    <p>
                        No candidate response plans
                        are available.
                    </p>

                </div>

            </section>
        );
    }


    const selectedName =
        selected.plan_name;


    return (
        <section className="detail-panel full-width-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        Digital Twin Plan Comparison
                    </h3>

                    <p>
                        Comparison of simulated
                        response strategies under
                        the current heuristic model.
                    </p>

                </div>


                <div className="plan-count">

                    {plans.length}
                    {" "}
                    plans

                </div>

            </div>


            <div className="plan-grid">

                {plans.map(
                    (
                        plan,
                        index
                    ) => {

                    const planName =
                        plan.plan_name
                        || plan.name
                        || `Plan ${index + 1}`;

                    const isSelected =
                        planName
                        === selectedName;


                    const residualRisk =
                        plan.predicted_residual_risk
                        ?? plan.residual_risk
                        ?? "-";


                    const reduction =
                        plan.risk_reduction_percentage
                        ?? plan.risk_reduction
                        ?? "-";


                    const impact =
                        plan.operational_impact
                        ?? "-";


                    const score =
                        plan.score
                        ?? plan.plan_score
                        ?? plan.security_score
                        ?? "-";


                    return (

                        <div
                            key={
                                plan.plan_id
                                || planName
                            }
                            className={
                                isSelected
                                    ? "plan-card selected"
                                    : "plan-card"
                            }
                        >

                            <div className="plan-card-header">

                                <div>

                                    <span className="plan-number">
                                        PLAN {index + 1}
                                    </span>

                                    <h4>
                                        {planName}
                                    </h4>

                                </div>


                                {isSelected && (

                                    <span className="selected-plan-badge">
                                        SELECTED
                                    </span>

                                )}

                            </div>


                            <div className="plan-metrics">

                                <Metric
                                    label="Residual Risk"
                                    value={
                                        residualRisk
                                    }
                                />

                                <Metric
                                    label="Risk Reduction"
                                    value={
                                        formatPercent(
                                            reduction
                                        )
                                    }
                                />

                                <Metric
                                    label="Operational Impact"
                                    value={
                                        impact
                                    }
                                />

                                <Metric
                                    label="Plan Score"
                                    value={
                                        score
                                    }
                                />

                            </div>


                            <RiskBar
                                residualRisk={
                                    residualRisk
                                }
                            />

                        </div>
                    );
                })}

            </div>


            <div className="digital-twin-note">

                <strong>
                    Model note:
                </strong>

                {" "}

                Digital Twin scores are deterministic
                heuristic decision-support values.
                They are not calibrated probabilities
                of real-world compromise or recovery.

            </div>

        </section>
    );
}


function Metric({
    label,
    value,
}) {
    return (
        <div className="plan-metric">

            <span>
                {label}
            </span>

            <strong>
                {value}
            </strong>

        </div>
    );
}


function formatPercent(
    value
) {
    if (
        value === null
        || value === undefined
        || value === "-"
    ) {
        return "-";
    }

    const text =
        String(value);

    if (
        text.includes("%")
    ) {
        return text;
    }

    return `${value}%`;
}


function RiskBar({
    residualRisk,
}) {
    const number =
        Number(
            residualRisk
        );

    const safeValue =
        Number.isNaN(number)
            ? 0
            : Math.min(
                100,
                Math.max(
                    0,
                    number
                )
            );


    return (
        <div className="risk-bar-wrapper">

            <div className="risk-bar-label">

                <span>
                    Modeled residual risk
                </span>

                <strong>
                    {safeValue}
                </strong>

            </div>


            <div className="risk-bar">

                <div
                    className="risk-bar-fill"
                    style={{
                        width:
                            `${safeValue}%`,
                    }}
                />

            </div>

        </div>
    );
}


export default PlanComparison;