import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getSOCHealth,
  getSOCDashboardSummary,
  getSOCCases,
  getSOCTickets,
} from "../services/socApi";

import "./SOCDashboard.css";


// ================================================================
// HELPERS
// ================================================================

function safeNumber(value) {
  const parsed = Number(value);

  if (Number.isFinite(parsed)) {
    return parsed;
  }

  return 0;
}


function safeArray(value) {
  return Array.isArray(value)
    ? value
    : [];
}


function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString();
}


function severityClass(value) {
  const severity = String(
    value || ""
  ).toUpperCase();

  if (severity === "CRITICAL") {
    return "severity critical";
  }

  if (severity === "HIGH") {
    return "severity high";
  }

  if (severity === "MEDIUM") {
    return "severity medium";
  }

  if (severity === "LOW") {
    return "severity low";
  }

  return "severity info";
}


function ticketPriorityClass(value) {
  const priority = String(
    value || ""
  ).toUpperCase();

  if (priority === "P1") {
    return "priority priority-p1";
  }

  if (priority === "P2") {
    return "priority priority-p2";
  }

  if (priority === "P3") {
    return "priority priority-p3";
  }

  return "priority priority-p4";
}


// ================================================================
// STAT CARD
// ================================================================

function StatCard({
  title,
  value,
  subtitle,
  tone = "blue",
}) {
  return (
    <div
      className={`soc-stat-card tone-${tone}`}
    >
      <div className="soc-stat-card-top">
        <span className="soc-stat-label">
          {title}
        </span>

        <span
          className={`soc-stat-dot dot-${tone}`}
        />
      </div>

      <div className="soc-stat-value">
        {value}
      </div>

      <div className="soc-stat-subtitle">
        {subtitle}
      </div>
    </div>
  );
}


// ================================================================
// SECTION HEADER
// ================================================================

function SectionHeader({
  title,
  subtitle,
}) {
  return (
    <div className="soc-section-header">
      <div>
        <h2>
          {title}
        </h2>

        {subtitle && (
          <p>
            {subtitle}
          </p>
        )}
      </div>
    </div>
  );
}


// ================================================================
// MAIN DASHBOARD
// ================================================================

export default function SOCDashboard() {

  const [
    health,
    setHealth,
  ] = useState(null);

  const [
    summary,
    setSummary,
  ] = useState(null);

  const [
    cases,
    setCases,
  ] = useState([]);

  const [
    tickets,
    setTickets,
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
    lastRefresh,
    setLastRefresh,
  ] = useState(null);


  // ==============================================================
  // LOAD DASHBOARD DATA
  // ==============================================================

  const loadDashboard = useCallback(
    async () => {

      setLoading(true);
      setError("");

      try {

        const [
          healthResult,
          summaryResult,
          casesResult,
          ticketsResult,
        ] = await Promise.all([
          getSOCHealth(),
          getSOCDashboardSummary(),
          getSOCCases(100),
          getSOCTickets(100),
        ]);


        setHealth(
          healthResult || {}
        );

        setSummary(
          summaryResult || {}
        );

        setCases(
          safeArray(
            casesResult?.cases
          )
        );

        setTickets(
          safeArray(
            ticketsResult?.tickets
          )
        );

        setLastRefresh(
          new Date()
        );

      } catch (requestError) {

        console.error(
          "Unable to load SOC dashboard:",
          requestError
        );

        setError(
          requestError?.message ||
          "Unable to connect to the SENTINEL-X SOC backend."
        );

      } finally {

        setLoading(false);
      }
    },
    []
  );


  useEffect(
    () => {

      loadDashboard();

      const interval = setInterval(
        loadDashboard,
        15000
      );

      return () =>
        clearInterval(
          interval
        );

    },
    [loadDashboard]
  );


  // ==============================================================
  // CALCULATED VALUES
  // ==============================================================

  const recentCases = useMemo(
    () => {

      return [...cases]
        .sort(
          (a, b) => {

            const aTime = new Date(
              a.updated_at ||
              a.created_at ||
              0
            ).getTime();

            const bTime = new Date(
              b.updated_at ||
              b.created_at ||
              0
            ).getTime();

            return bTime - aTime;
          }
        )
        .slice(
          0,
          6
        );

    },
    [cases]
  );


  const recentTickets = useMemo(
    () => {

      return [...tickets]
        .sort(
          (a, b) => {

            const aTime = new Date(
              a.updated_at ||
              a.created_at ||
              0
            ).getTime();

            const bTime = new Date(
              b.updated_at ||
              b.created_at ||
              0
            ).getTime();

            return bTime - aTime;
          }
        )
        .slice(
          0,
          6
        );

    },
    [tickets]
  );


  const priorityCounts =
    summary?.priority_counts || {};


  const totalPriorities =
    safeNumber(
      priorityCounts.P1
    )
    +
    safeNumber(
      priorityCounts.P2
    )
    +
    safeNumber(
      priorityCounts.P3
    )
    +
    safeNumber(
      priorityCounts.P4
    );


  // ==============================================================
  // LOADING VIEW
  // ==============================================================

  if (
    loading &&
    !summary
  ) {

    return (
      <div className="soc-dashboard-page">

        <div className="soc-loading-container">

          <div className="soc-spinner" />

          <h2>
            Loading SENTINEL-X SOC
          </h2>

          <p>
            Retrieving persistent incidents,
            tickets and response state...
          </p>

        </div>

      </div>
    );
  }


  // ==============================================================
  // PAGE
  // ==============================================================

  return (
    <div className="soc-dashboard-page">

      {/* =========================================================
          HEADER
      ========================================================== */}

      <div className="soc-dashboard-header">

        <div>

          <div className="soc-eyebrow">
            SENTINEL-X
          </div>

          <h1>
            Security Operations Center
          </h1>

          <p>
            Autonomous multi-agent incident
            intelligence and response management
          </p>

        </div>


        <div className="soc-header-actions">

          <div className="soc-system-status">

            <span
              className={
                health?.status === "HEALTHY"
                  ? "system-dot online"
                  : "system-dot offline"
              }
            />

            <div>
              <span>
                SOC Backend
              </span>

              <strong>
                {health?.status || "UNKNOWN"}
              </strong>
            </div>

          </div>


          <button
            type="button"
            className="soc-refresh-button"
            onClick={
              loadDashboard
            }
            disabled={
              loading
            }
          >
            {loading
              ? "Refreshing..."
              : "Refresh"}
          </button>

        </div>

      </div>


      {/* =========================================================
          SAFETY / MODE BANNER
      ========================================================== */}

      <div className="soc-mode-banner">

        <div>

          <strong>
            AUTONOMY MODE
          </strong>

          <span>
            Analyst-supervised simulation
          </span>

        </div>

        <div className="soc-mode-tags">

          <span className="mode-tag simulation">
            SIMULATION MODE
          </span>

          <span className="mode-tag disabled">
            REAL RESPONSE DISABLED
          </span>

          <span className="mode-tag persistent">
            PERSISTENCE ACTIVE
          </span>

        </div>

      </div>


      {/* =========================================================
          ERROR
      ========================================================== */}

      {error && (

        <div className="soc-error">

          <strong>
            Backend connection issue
          </strong>

          <span>
            {error}
          </span>

        </div>

      )}


      {/* =========================================================
          KPI CARDS
      ========================================================== */}

      <div className="soc-stat-grid">

        <StatCard
          title="SOC Cases"
          value={
            safeNumber(
              summary?.persistent_soc_cases
            )
          }
          subtitle="Persistent incident cases"
          tone="blue"
        />

        <StatCard
          title="Critical Cases"
          value={
            safeNumber(
              summary?.critical_cases
            )
          }
          subtitle="Critical risk investigations"
          tone="red"
        />

        <StatCard
          title="High Risk"
          value={
            safeNumber(
              summary?.high_cases
            )
          }
          subtitle="High-severity cases"
          tone="orange"
        />

        <StatCard
          title="Open Tickets"
          value={
            safeNumber(
              summary?.open_tickets
            )
          }
          subtitle="Active SOC work items"
          tone="purple"
        />

        <StatCard
          title="Pending Approval"
          value={
            safeNumber(
              summary?.pending_approvals
            )
          }
          subtitle="Waiting for analyst decision"
          tone="yellow"
        />

        <StatCard
          title="Ready Actions"
          value={
            safeNumber(
              summary?.ready_response_actions
            )
          }
          subtitle="Approved simulated actions"
          tone="green"
        />

      </div>


      {/* =========================================================
          MAIN GRID
      ========================================================== */}

      <div className="soc-main-grid">

        {/* =======================================================
            PRIORITY DISTRIBUTION
        ======================================================== */}

        <div className="soc-panel">

          <SectionHeader
            title="Ticket Priority"
            subtitle="Current SOC workload distribution"
          />

          <div className="priority-chart">

            {[
              [
                "P1",
                safeNumber(
                  priorityCounts.P1
                ),
              ],

              [
                "P2",
                safeNumber(
                  priorityCounts.P2
                ),
              ],

              [
                "P3",
                safeNumber(
                  priorityCounts.P3
                ),
              ],

              [
                "P4",
                safeNumber(
                  priorityCounts.P4
                ),
              ],

            ].map(
              ([priority, count]) => {

                const percentage =
                  totalPriorities > 0
                    ? (
                        count /
                        totalPriorities
                      ) * 100
                    : 0;

                return (
                  <div
                    className="priority-row"
                    key={
                      priority
                    }
                  >

                    <div className="priority-row-header">

                      <span
                        className={
                          ticketPriorityClass(
                            priority
                          )
                        }
                      >
                        {priority}
                      </span>

                      <span>
                        {count}
                      </span>

                    </div>


                    <div className="priority-track">

                      <div
                        className={`priority-fill fill-${priority.toLowerCase()}`}
                        style={{
                          width:
                            `${percentage}%`,
                        }}
                      />

                    </div>

                  </div>
                );
              }
            )}

          </div>

        </div>


        {/* =======================================================
            RESPONSE STATUS
        ======================================================== */}

        <div className="soc-panel">

          <SectionHeader
            title="Response Workflow"
            subtitle="Policy-controlled response state"
          />

          <div className="workflow-metrics">

            <div className="workflow-metric">

              <span>
                Total Actions
              </span>

              <strong>
                {
                  safeNumber(
                    summary?.total_response_actions
                  )
                }
              </strong>

            </div>


            <div className="workflow-metric">

              <span>
                Pending Actions
              </span>

              <strong>
                {
                  safeNumber(
                    summary?.pending_response_actions
                  )
                }
              </strong>

            </div>


            <div className="workflow-metric">

              <span>
                Ready Actions
              </span>

              <strong>
                {
                  safeNumber(
                    summary?.ready_response_actions
                  )
                }
              </strong>

            </div>


            <div className="workflow-metric">

              <span>
                Approved Tickets
              </span>

              <strong>
                {
                  safeNumber(
                    summary?.approved_tickets
                  )
                }
              </strong>

            </div>


            <div className="workflow-metric">

              <span>
                Rejected Tickets
              </span>

              <strong>
                {
                  safeNumber(
                    summary?.rejected_tickets
                  )
                }
              </strong>

            </div>


            <div className="workflow-metric">

              <span>
                Execution
              </span>

              <strong className="safe-text">
                SIMULATION
              </strong>

            </div>

          </div>

        </div>


        {/* =======================================================
            SYSTEM INTELLIGENCE STATUS
        ======================================================== */}

        <div className="soc-panel">

          <SectionHeader
            title="Platform Status"
            subtitle="Core SENTINEL-X services"
          />

          <div className="service-list">

            <div className="service-row">

              <div>
                <span className="service-dot active" />
                Multi-Agent Intelligence
              </div>

              <strong>
                ACTIVE
              </strong>

            </div>


            <div className="service-row">

              <div>
                <span className="service-dot active" />
                Incident Correlation
              </div>

              <strong>
                ACTIVE
              </strong>

            </div>


            <div className="service-row">

              <div>
                <span className="service-dot active" />
                Digital Twin
              </div>

              <strong>
                ACTIVE
              </strong>

            </div>


            <div className="service-row">

              <div>
                <span className="service-dot active" />
                Persistent Recovery
              </div>

              <strong>
                {
                  health?.persistent_recovery
                    ? "ACTIVE"
                    : "UNKNOWN"
                }
              </strong>

            </div>


            <div className="service-row">

              <div>
                <span className="service-dot active" />
                Evidence Persistence
              </div>

              <strong>
                {
                  health?.evidence_persistence
                    ? "ACTIVE"
                    : "UNKNOWN"
                }
              </strong>

            </div>


            <div className="service-row">

              <div>
                <span className="service-dot safe" />
                Real Response Execution
              </div>

              <strong className="safe-text">
                DISABLED
              </strong>

            </div>

          </div>

        </div>

      </div>


      {/* =========================================================
          RECENT CASES
      ========================================================== */}

      <div className="soc-table-panel">

        <SectionHeader
          title="Recent SOC Cases"
          subtitle="Latest persistent incidents under investigation"
        />


        {recentCases.length === 0 ? (

          <div className="soc-empty-state">

            <strong>
              No persistent cases yet
            </strong>

            <span>
              Incidents created by the unified SOC
              workflow will appear here.
            </span>

          </div>

        ) : (

          <div className="soc-table-wrapper">

            <table className="soc-table">

              <thead>
                <tr>
                  <th>
                    Incident
                  </th>

                  <th>
                    Risk
                  </th>

                  <th>
                    Status
                  </th>

                  <th>
                    Priority
                  </th>

                  <th>
                    Updated
                  </th>
                </tr>
              </thead>


              <tbody>

                {recentCases.map(
                  (
                    incident,
                    index
                  ) => {

                    const incidentId =
                      incident.incident_id ||
                      incident.id ||
                      `incident-${index}`;

                    const riskLevel =
                      incident.risk_level ||
                      incident.severity ||
                      incident.ticket_data
                        ?.risk_level ||
                      "INFO";

                    const status =
                      incident.case_status ||
                      incident.status ||
                      "UNKNOWN";

                    const priority =
                      incident.priority ||
                      incident.ticket_data
                        ?.priority ||
                      "—";


                    return (
                      <tr
                        key={
                          incidentId
                        }
                      >

                        <td>

                          <div className="incident-cell">

                            <strong>
                              {incidentId}
                            </strong>

                            <span>
                              {
                                incident.title ||
                                incident.ticket_data
                                  ?.title ||
                                "SOC Incident"
                              }
                            </span>

                          </div>

                        </td>


                        <td>

                          <span
                            className={
                              severityClass(
                                riskLevel
                              )
                            }
                          >
                            {riskLevel}
                          </span>

                        </td>


                        <td>
                          {status}
                        </td>


                        <td>
                          {priority}
                        </td>


                        <td>
                          {
                            formatDate(
                              incident.updated_at ||
                              incident.created_at
                            )
                          }
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


      {/* =========================================================
          RECENT TICKETS
      ========================================================== */}

      <div className="soc-table-panel">

        <SectionHeader
          title="Recent SOC Tickets"
          subtitle="Human-in-the-loop investigation and approval queue"
        />


        {recentTickets.length === 0 ? (

          <div className="soc-empty-state">

            <strong>
              No tickets available
            </strong>

            <span>
              Tickets created from investigated
              incidents will appear here.
            </span>

          </div>

        ) : (

          <div className="soc-table-wrapper">

            <table className="soc-table">

              <thead>
                <tr>
                  <th>
                    Ticket
                  </th>

                  <th>
                    Priority
                  </th>

                  <th>
                    Risk
                  </th>

                  <th>
                    Approval
                  </th>

                  <th>
                    Status
                  </th>
                </tr>
              </thead>


              <tbody>

                {recentTickets.map(
                  (
                    ticket,
                    index
                  ) => {

                    const ticketId =
                      ticket.ticket_id ||
                      ticket.id ||
                      `ticket-${index}`;

                    return (
                      <tr
                        key={
                          ticketId
                        }
                      >

                        <td>

                          <div className="incident-cell">

                            <strong>
                              {ticketId}
                            </strong>

                            <span>
                              {
                                ticket.title ||
                                ticket.incident_id ||
                                "SOC Ticket"
                              }
                            </span>

                          </div>

                        </td>


                        <td>

                          <span
                            className={
                              ticketPriorityClass(
                                ticket.priority
                              )
                            }
                          >
                            {
                              ticket.priority ||
                              "P4"
                            }
                          </span>

                        </td>


                        <td>

                          <span
                            className={
                              severityClass(
                                ticket.risk_level
                              )
                            }
                          >
                            {
                              ticket.risk_level ||
                              "INFO"
                            }
                          </span>

                        </td>


                        <td>
                          {
                            ticket.approval_status ||
                            "NOT REQUIRED"
                          }
                        </td>


                        <td>
                          {
                            ticket.status ||
                            "OPEN"
                          }
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


      {/* =========================================================
          FOOTER
      ========================================================== */}

      <div className="soc-dashboard-footer">

        <span>
          SENTINEL-X Autonomous Multi-Agent SOC
        </span>

        <span>
          Last refresh:{" "}
          {
            lastRefresh
              ? lastRefresh.toLocaleTimeString()
              : "—"
          }
        </span>

      </div>

    </div>
  );
}