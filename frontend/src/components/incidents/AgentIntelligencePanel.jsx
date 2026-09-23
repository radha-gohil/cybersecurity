import "./AgentIntelligencePanel.css";

function safeObject(value) {
    return (
        value
        && typeof value === "object"
        && !Array.isArray(value)
    )
        ? value
        : {};
}


function safeArray(value) {
    return Array.isArray(value)
        ? value
        : [];
}


function displayValue(value) {

    if (
        value === null
        || value === undefined
        || value === ""
    ) {
        return "-";
    }


    if (
        typeof value === "object"
    ) {
        return JSON.stringify(
            value
        );
    }


    return String(
        value
    );
}


function severityClass(
    value
) {

    const severity =
        String(
            value || ""
        ).toUpperCase();


    if (
        severity === "CRITICAL"
    ) {
        return "badge critical";
    }


    if (
        severity === "HIGH"
    ) {
        return "badge high";
    }


    if (
        severity === "MEDIUM"
    ) {
        return "badge medium";
    }


    if (
        severity === "LOW"
    ) {
        return "badge low";
    }


    return "badge neutral";
}


function AgentCard({
    title,
    subtitle,
    data,
}) {

    const safeData =
        safeObject(
            data
        );


    const decision =
        safeData.decision
        || safeData.final_decision
        || safeData.recommendation
        || safeData.priority
        || "-";


    const confidence =
        safeData.confidence
        ?? safeData.consensus_confidence
        ?? safeData.score
        ?? "-";


    const severity =
        safeData.severity
        || safeData.risk_level
        || safeData.threat_level
        || "-";


    const reasoning =
        safeData.reasoning
        || safeData.reason
        || safeData.assessment
        || safeData.explanation
        || safeData.summary
        || "";


    return (

        <div className="agent-card">

            <div className="agent-card-heading">

                <div>

                    <h4>
                        {title}
                    </h4>

                    <p>
                        {subtitle}
                    </p>

                </div>


                {
                    severity !== "-"
                    && (

                        <span
                            className={
                                severityClass(
                                    severity
                                )
                            }
                        >
                            {severity}
                        </span>

                    )
                }

            </div>


            <div className="agent-card-metrics">

                <div>

                    <span>
                        Decision
                    </span>

                    <strong>
                        {
                            displayValue(
                                decision
                            )
                        }
                    </strong>

                </div>


                <div>

                    <span>
                        Confidence / Score
                    </span>

                    <strong>
                        {
                            displayValue(
                                confidence
                            )
                        }
                    </strong>

                </div>

            </div>


            {
                reasoning
                ? (

                    <div className="agent-reasoning">

                        <span>
                            Reasoning
                        </span>

                        {
                            Array.isArray(
                                reasoning
                            )
                                ? (

                                    <ul>

                                        {
                                            reasoning.map(
                                                (
                                                    item,
                                                    index
                                                ) => (

                                                    <li
                                                        key={
                                                            index
                                                        }
                                                    >
                                                        {
                                                            displayValue(
                                                                item
                                                            )
                                                        }
                                                    </li>

                                                )
                                            )
                                        }

                                    </ul>

                                )
                                : (

                                    <p>
                                        {
                                            displayValue(
                                                reasoning
                                            )
                                        }
                                    </p>

                                )
                        }

                    </div>

                )
                : null
            }

        </div>
    );
}


function AgentIntelligencePanel({
    intelligence,
}) {

    const wrapper =
        safeObject(
            intelligence
        );


    const data =
        safeObject(
            wrapper.data
            || wrapper
        );


    const coordinated =
        safeObject(
            data.coordinated_analysis
        );


    const triage =
        safeObject(
            data.triage
            || coordinated.triage
        );


    const investigation =
        safeObject(
            data.investigation
            || coordinated.investigation
        );


    const risk =
        safeObject(
            data.risk
            || data.risk_assessment
            || coordinated.risk
            || coordinated.risk_assessment
        );


    const consensus =
        safeObject(
            data.agent_consensus
            || data.consensus
            || coordinated.agent_consensus
            || coordinated.consensus
        );


    const standardizedDecisions =
        safeArray(
            data.standardized_agent_decisions
            || data.agent_decisions
            || coordinated.standardized_agent_decisions
            || coordinated.agent_decisions
        );


    const hasStructuredData =
        Object.keys(
            triage
        ).length > 0
        ||
        Object.keys(
            investigation
        ).length > 0
        ||
        Object.keys(
            risk
        ).length > 0
        ||
        Object.keys(
            consensus
        ).length > 0
        ||
        standardizedDecisions.length > 0;


    if (
        !wrapper.available
        && !hasStructuredData
    ) {

        return (

            <section className="detail-panel full-width-panel">

                <div className="panel-heading">

                    <div>

                        <h3>
                            Multi-Agent Intelligence
                        </h3>

                        <p>
                            Investigation and decision support
                            from SENTINEL-X agents.
                        </p>

                    </div>

                </div>


                <div className="empty-inline">

                    No multi-agent intelligence is
                    available for this incident.

                </div>

            </section>
        );
    }


    return (

        <section className="detail-panel full-width-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        Multi-Agent Intelligence
                    </h3>

                    <p>
                        Specialized agents analyze,
                        investigate and assess the incident
                        using shared incident context.
                    </p>

                </div>

            </div>


            <div className="agent-grid">

                {
                    Object.keys(
                        triage
                    ).length > 0
                    && (

                        <AgentCard
                            title="Triage Agent"
                            subtitle="Initial prioritization and investigation decision"
                            data={
                                triage
                            }
                        />

                    )
                }


                {
                    Object.keys(
                        investigation
                    ).length > 0
                    && (

                        <AgentCard
                            title="Investigation Agent"
                            subtitle="Evidence analysis and incident reasoning"
                            data={
                                investigation
                            }
                        />

                    )
                }


                {
                    Object.keys(
                        risk
                    ).length > 0
                    && (

                        <AgentCard
                            title="Risk Assessment Agent"
                            subtitle="Risk severity and response requirement"
                            data={
                                risk
                            }
                        />

                    )
                }


                {
                    Object.keys(
                        consensus
                    ).length > 0
                    && (

                        <AgentCard
                            title="Agent Consensus"
                            subtitle="Combined decision across participating agents"
                            data={
                                consensus
                            }
                        />

                    )
                }

            </div>


            {
                standardizedDecisions.length > 0
                && (

                    <div className="agent-decision-section">

                        <h4>
                            Standardized Agent Decisions
                        </h4>


                        <div className="table-container">

                            <table className="soc-table">

                                <thead>

                                    <tr>

                                        <th>
                                            Agent
                                        </th>

                                        <th>
                                            Decision
                                        </th>

                                        <th>
                                            Confidence
                                        </th>

                                        <th>
                                            Severity
                                        </th>

                                    </tr>

                                </thead>


                                <tbody>

                                    {
                                        standardizedDecisions.map(
                                            (
                                                decision,
                                                index
                                            ) => (

                                                <tr
                                                    key={
                                                        decision.agent
                                                        || index
                                                    }
                                                >

                                                    <td>

                                                        <strong>
                                                            {
                                                                decision.agent
                                                                || decision.agent_name
                                                                || "-"
                                                            }
                                                        </strong>

                                                    </td>


                                                    <td>
                                                        {
                                                            decision.decision
                                                            || "-"
                                                        }
                                                    </td>


                                                    <td>
                                                        {
                                                            displayValue(
                                                                decision.confidence
                                                                ?? decision.score
                                                            )
                                                        }
                                                    </td>


                                                    <td>

                                                        <span
                                                            className={
                                                                severityClass(
                                                                    decision.severity
                                                                )
                                                            }
                                                        >
                                                            {
                                                                decision.severity
                                                                || "-"
                                                            }
                                                        </span>

                                                    </td>

                                                </tr>

                                            )
                                        )
                                    }

                                </tbody>

                            </table>

                        </div>

                    </div>

                )
            }


            <details className="timeline-details">

                <summary>
                    View raw intelligence data
                </summary>


                <pre className="incident-json-block">

                    {
                        JSON.stringify(
                            data,
                            null,
                            2
                        )
                    }

                </pre>

            </details>

        </section>
    );
}


export default AgentIntelligencePanel;