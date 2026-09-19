function EvidencePanel({
    evidence = {},
}) {
    const processes =
        evidence.processes || [];

    const files =
        evidence.files || [];

    const network =
        evidence.network_connections || [];

    const registry =
        evidence.registry_artifacts || [];


    return (
        <section className="detail-panel full-width-panel">

            <div className="panel-heading">

                <h3>
                    Investigation Evidence
                </h3>

                <p>
                    Persistent process, file, network
                    and registry artifacts associated
                    with the incident.
                </p>

            </div>


            <div className="evidence-summary-row">

                <EvidenceCounter
                    label="Processes"
                    value={processes.length}
                />

                <EvidenceCounter
                    label="Files"
                    value={files.length}
                />

                <EvidenceCounter
                    label="Network"
                    value={network.length}
                />

                <EvidenceCounter
                    label="Registry"
                    value={registry.length}
                />

            </div>


            <div className="evidence-section">

                <h4>
                    Process Evidence
                </h4>

                {processes.length === 0 ? (
                    <EmptyEvidence />
                ) : (

                    <div className="table-container">

                        <table className="soc-table">

                            <thead>
                                <tr>
                                    <th>PID</th>
                                    <th>Process</th>
                                    <th>Executable</th>
                                    <th>Behavior</th>
                                    <th>Anomaly</th>
                                    <th>Threat Score</th>
                                </tr>
                            </thead>

                            <tbody>

                                {processes.map(
                                    (
                                        item,
                                        index
                                    ) => (

                                    <tr key={index}>

                                        <td>
                                            {
                                                item.pid
                                                ?? "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                item.name
                                                || item.process_name
                                                || "-"
                                            }
                                        </td>

                                        <td className="mono-text evidence-path">
                                            {
                                                item.exe
                                                || item.path
                                                || "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                item.behavior_score
                                                ?? "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                item.anomaly_score
                                                ?? "-"
                                            }
                                        </td>

                                        <td>
                                            <RiskValue
                                                value={
                                                    item.combined_threat_score
                                                    ?? item.threat_score
                                                }
                                            />
                                        </td>

                                    </tr>
                                ))}

                            </tbody>

                        </table>

                    </div>
                )}

            </div>


            <div className="evidence-section">

                <h4>
                    File Evidence
                </h4>

                {files.length === 0 ? (
                    <EmptyEvidence />
                ) : (

                    <div className="table-container">

                        <table className="soc-table">

                            <thead>
                                <tr>
                                    <th>File</th>
                                    <th>Path</th>
                                    <th>SHA-256</th>
                                    <th>Malware Probability</th>
                                    <th>Static Risk</th>
                                </tr>
                            </thead>

                            <tbody>

                                {files.map(
                                    (
                                        item,
                                        index
                                    ) => (

                                    <tr key={index}>

                                        <td>
                                            {
                                                item.name
                                                || "-"
                                            }
                                        </td>

                                        <td className="mono-text evidence-path">
                                            {
                                                item.path
                                                || "-"
                                            }
                                        </td>

                                        <td className="mono-text hash-cell">
                                            {
                                                item.sha256
                                                || "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                formatProbability(
                                                    item.malware_probability
                                                )
                                            }
                                        </td>

                                        <td>
                                            <RiskValue
                                                value={
                                                    item.static_risk_score
                                                }
                                            />
                                        </td>

                                    </tr>
                                ))}

                            </tbody>

                        </table>

                    </div>
                )}

            </div>


            <div className="evidence-section">

                <h4>
                    Network Evidence
                </h4>

                {network.length === 0 ? (
                    <EmptyEvidence />
                ) : (

                    <div className="table-container">

                        <table className="soc-table">

                            <thead>
                                <tr>
                                    <th>PID</th>
                                    <th>Process</th>
                                    <th>Remote IP</th>
                                    <th>Remote Port</th>
                                </tr>
                            </thead>

                            <tbody>

                                {network.map(
                                    (
                                        item,
                                        index
                                    ) => (

                                    <tr key={index}>

                                        <td>
                                            {
                                                item.pid
                                                ?? "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                item.process_name
                                                || item.name
                                                || "-"
                                            }
                                        </td>

                                        <td className="mono-text">
                                            {
                                                item.remote_ip
                                                || "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                item.remote_port
                                                ?? "-"
                                            }
                                        </td>

                                    </tr>
                                ))}

                            </tbody>

                        </table>

                    </div>
                )}

            </div>


            <div className="evidence-section">

                <h4>
                    Registry Evidence
                </h4>

                {registry.length === 0 ? (
                    <EmptyEvidence />
                ) : (

                    <div className="table-container">

                        <table className="soc-table">

                            <thead>
                                <tr>
                                    <th>Registry Key</th>
                                    <th>Value Name</th>
                                    <th>Value Data</th>
                                </tr>
                            </thead>

                            <tbody>

                                {registry.map(
                                    (
                                        item,
                                        index
                                    ) => (

                                    <tr key={index}>

                                        <td className="mono-text evidence-path">
                                            {
                                                item.key
                                                || "-"
                                            }
                                        </td>

                                        <td>
                                            {
                                                item.value_name
                                                || "-"
                                            }
                                        </td>

                                        <td className="mono-text evidence-path">
                                            {
                                                item.value_data
                                                || "-"
                                            }
                                        </td>

                                    </tr>
                                ))}

                            </tbody>

                        </table>

                    </div>
                )}

            </div>

        </section>
    );
}


function EvidenceCounter({
    label,
    value,
}) {
    return (
        <div className="evidence-counter">

            <span>
                {label}
            </span>

            <strong>
                {value}
            </strong>

        </div>
    );
}


function EmptyEvidence() {
    return (
        <div className="empty-inline">
            No evidence available.
        </div>
    );
}


function formatProbability(
    value
) {
    if (
        value === null
        || value === undefined
    ) {
        return "-";
    }

    const number =
        Number(value);

    if (
        Number.isNaN(number)
    ) {
        return String(value);
    }

    if (number <= 1) {
        return `${(
            number * 100
        ).toFixed(1)}%`;
    }

    return `${number.toFixed(1)}%`;
}


function RiskValue({
    value,
}) {
    if (
        value === null
        || value === undefined
    ) {
        return "-";
    }

    const number =
        Number(value);

    let className =
        "risk-value low";

    if (number >= 80) {
        className =
            "risk-value critical";
    } else if (number >= 60) {
        className =
            "risk-value high";
    } else if (number >= 35) {
        className =
            "risk-value medium";
    }

    return (
        <span className={className}>
            {value}
        </span>
    );
}


export default EvidencePanel;