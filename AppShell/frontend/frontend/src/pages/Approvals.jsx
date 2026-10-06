import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  Stack,
  TextField,
  Typography,
} from "@mui/material";

import {
  ApprovalRounded,
  CancelRounded,
  CheckCircleRounded,
  RefreshRounded,
  ScienceRounded,
  PsychologyRounded,
  ShieldRounded,
} from "@mui/icons-material";

import api, {
  approveIncident,
  rejectIncident,
} from "../api/sentinelApi";

function obj(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
}

function arr(value) {
  return Array.isArray(value) ? value : [];
}

function text(value, fallback = "Not available") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function apiError(error) {
  const detail = error?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (detail) return JSON.stringify(detail);
  return error?.message || "Request failed.";
}

function normalizeApproval(status) {
  const value = String(status || "UNKNOWN").toUpperCase();
  if (value.includes("APPROV")) return "APPROVED";
  if (value.includes("REJECT")) return "REJECTED";
  if (
    value.includes("PENDING") ||
    value.includes("AWAIT") ||
    value.includes("REVIEW")
  ) {
    return "PENDING";
  }
  return value;
}

function statusColor(status) {
  if (status === "APPROVED") return "#22c55e";
  if (status === "REJECTED") return "#ef4444";
  if (status === "PENDING") return "#f59e0b";
  return "#94a3b8";
}

function summarizeTarget(target) {
  if (!target || typeof target !== "object") {
    return text(target);
  }

  const processes = arr(target.processes);
  if (processes.length) {
    return processes
      .map((process) => {
        const name = process?.name || process?.process_name || "process";
        const pid = process?.pid;
        return pid ? `${name} (PID ${pid})` : name;
      })
      .join(", ");
  }

  const files = arr(target.files);
  if (files.length) {
    return files
      .map((file) => file?.path || file?.name || "file")
      .join(", ");
  }

  const network = arr(target.network || target.connections);
  if (network.length) {
    return network
      .map((item) => {
        const ip = item?.remote_ip || item?.ip || "network target";
        const port = item?.remote_port || item?.port;
        return port ? `${ip}:${port}` : ip;
      })
      .join(", ");
  }

  return JSON.stringify(target);
}

function normalizeCase(caseData) {
  const record = obj(caseData);
  const ticket = obj(record.ticket);
  const decision = obj(record.decision);
  const bestPlan = obj(decision.best_plan);
  const actions = arr(record.response_actions);

  const approvalStatus = normalizeApproval(
    ticket.approval_status ||
      actions[0]?.approval_status ||
      record.approval_status
  );

  return {
    incidentId: String(record.incident_id || ""),
    caseStatus: record.status,
    ticketId: ticket.ticket_id,
    ticketStatus: ticket.status,
    priority: ticket.priority,
    riskScore:
      ticket.risk_score ?? decision.initial_risk_score ?? null,
    riskLevel: ticket.risk_level,
    selectedPlan:
      ticket.selected_plan || bestPlan.plan_name || decision.selected_plan_name,
    residualRisk:
      ticket.predicted_residual_risk ??
      bestPlan.predicted_residual_risk ??
      null,
    operationalImpact:
      ticket.operational_impact ||
      bestPlan?.operational_impact?.impact_level ||
      null,
    approvalStatus,
    assignedAnalyst: ticket.assigned_analyst,
    actions: actions.map((action) => ({
      id: action?.action_id,
      type: action?.action_type || "UNKNOWN_ACTION",
      target: summarizeTarget(action?.target),
      reason: action?.reason,
      approvalStatus: normalizeApproval(action?.approval_status),
      executionStatus: action?.execution_status,
      policyDecision: action?.policy_decision,
      riskLevel: action?.risk_level,
    })),
    simulationMode: record.simulation_mode !== false,
    realResponseExecuted: record.real_response_executed === true,
  };
}

function Metric({ label, value, color }) {
  return (
    <Card>
      <CardContent sx={{ p: 2.5 }}>
        <Typography sx={{ color: "#64748b", fontSize: 12 }}>
          {label}
        </Typography>
        <Typography sx={{ mt: 0.5, fontSize: 29, fontWeight: 800, color }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

function Info({ label, value }) {
  return (
    <Box
      sx={{
        p: 1.5,
        borderRadius: 2,
        bgcolor: "#0f172a",
        border: "1px solid #1e293b",
      }}
    >
      <Typography sx={{ color: "#64748b", fontSize: 11 }}>
        {label}
      </Typography>
      <Typography
        sx={{
          mt: 0.4,
          color: "#e2e8f0",
          fontSize: 13,
          fontWeight: 650,
          overflowWrap: "anywhere",
        }}
      >
        {text(value)}
      </Typography>
    </Box>
  );
}

function CaseCard({ item, onDecision, onOpenInvestigation, onOpenSimulator }) {
  const color = statusColor(item.approvalStatus);
  const pending = item.approvalStatus === "PENDING";

  return (
    <Card
      sx={{
        borderColor: pending
          ? "rgba(245,158,11,0.35)"
          : "#1e293b",
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Stack
          direction={{ xs: "column", lg: "row" }}
          justifyContent="space-between"
          spacing={3}
        >
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Stack direction="row" spacing={1} flexWrap="wrap" alignItems="center">
              <ApprovalRounded sx={{ color }} />
              <Typography variant="h6">
                {text(item.selectedPlan, "SOC Response Review")}
              </Typography>
              <Chip
                size="small"
                label={item.approvalStatus}
                sx={{
                  color,
                  border: `1px solid ${color}55`,
                  bgcolor: `${color}12`,
                }}
              />
              {item.priority && (
                <Chip size="small" variant="outlined" label={item.priority} />
              )}
            </Stack>

            <Typography
              sx={{ color: "#94a3b8", fontSize: 12, mt: 1, overflowWrap: "anywhere" }}
            >
              Incident {item.incidentId}
            </Typography>

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: {
                  xs: "1fr",
                  sm: "repeat(2,1fr)",
                  lg: "repeat(4,1fr)",
                },
                gap: 1.5,
                mt: 2,
              }}
            >
              <Info label="Case status" value={item.caseStatus} />
              <Info label="Ticket" value={item.ticketId} />
              <Info
                label="Investigation risk"
                value={
                  item.riskScore === null
                    ? null
                    : `${item.riskScore}${item.riskLevel ? ` ${item.riskLevel}` : ""}`
                }
              />
              <Info label="Modeled residual risk" value={item.residualRisk} />
            </Box>

            <Divider sx={{ my: 2 }} />

            <Typography sx={{ fontWeight: 700, mb: 1 }}>
              Persisted response actions
            </Typography>

            {item.actions.length ? (
              <Stack spacing={1}>
                {item.actions.map((action, index) => (
                  <Box
                    key={action.id || index}
                    sx={{
                      p: 1.5,
                      bgcolor: "#0f172a",
                      borderRadius: 2,
                      border: "1px solid #1e293b",
                    }}
                  >
                    <Stack
                      direction={{ xs: "column", md: "row" }}
                      justifyContent="space-between"
                      spacing={1}
                    >
                      <Box>
                        <Typography sx={{ fontWeight: 700 }}>
                          {String(action.type).replaceAll("_", " ")}
                        </Typography>
                        <Typography sx={{ color: "#94a3b8", fontSize: 12, mt: 0.4 }}>
                          Target: {text(action.target)}
                        </Typography>
                        <Typography sx={{ color: "#64748b", fontSize: 11, mt: 0.4 }}>
                          {text(action.reason)}
                        </Typography>
                      </Box>

                      <Stack direction="row" spacing={1} flexWrap="wrap">
                        <Chip size="small" label={`Approval ${action.approvalStatus}`} />
                        <Chip size="small" label={`Execution ${text(action.executionStatus)}`} />
                      </Stack>
                    </Stack>
                  </Box>
                ))}
              </Stack>
            ) : (
              <Alert severity="info">
                No persisted response action was found for this case.
              </Alert>
            )}
          </Box>

          <Stack spacing={1.2} sx={{ minWidth: { lg: 220 } }}>
            {pending && (
              <>
                <Button
                  variant="contained"
                  color="success"
                  startIcon={<CheckCircleRounded />}
                  onClick={() => onDecision(item, "APPROVE")}
                >
                  Approve Simulation
                </Button>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<CancelRounded />}
                  onClick={() => onDecision(item, "REJECT")}
                >
                  Reject
                </Button>
              </>
            )}

            <Button
              variant="outlined"
              startIcon={<ScienceRounded />}
              onClick={() => onOpenSimulator(item.incidentId)}
            >
              Response Simulator
            </Button>

            <Button
              variant="text"
              startIcon={<PsychologyRounded />}
              onClick={() => onOpenInvestigation(item.incidentId)}
            >
              AI Investigation
            </Button>
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
}

export default function Approvals() {
  const navigate = useNavigate();
  const location = useLocation();

  const incomingIncidentId = String(location.state?.incidentId || "");

  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [warnings, setWarnings] = useState([]);
  const [success, setSuccess] = useState("");

  const [dialog, setDialog] = useState(null);
  const [analyst, setAnalyst] = useState("");
  const [comment, setComment] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");

  const loadCases = useCallback(async () => {
    setLoading(true);
    setError("");
    setWarnings([]);

    try {
      const response = await api.get("/cases", {
        params: { limit: 1000 },
      });

      const summaries = arr(response.data?.cases);
      const loaded = [];
      const failures = [];

      for (const summary of summaries) {
        const incidentId = String(summary?.incident_id || summary?.id || "");
        if (!incidentId) {
          failures.push("A stored case has no incident ID.");
          continue;
        }

        try {
          const details = await api.get(
            `/cases/${encodeURIComponent(incidentId)}`
          );
          loaded.push(normalizeCase(details.data));
        } catch (requestError) {
          failures.push(`${incidentId}: ${apiError(requestError)}`);
        }
      }

      loaded.sort((a, b) => {
        if (a.incidentId === incomingIncidentId) return -1;
        if (b.incidentId === incomingIncidentId) return 1;
        if (a.approvalStatus === "PENDING" && b.approvalStatus !== "PENDING") return -1;
        if (b.approvalStatus === "PENDING" && a.approvalStatus !== "PENDING") return 1;
        return 0;
      });

      setCases(loaded);
      setWarnings(failures);
    } catch (requestError) {
      setCases([]);
      setError(apiError(requestError));
    } finally {
      setLoading(false);
    }
  }, [incomingIncidentId]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  const stats = useMemo(() => ({
    pending: cases.filter((item) => item.approvalStatus === "PENDING").length,
    approved: cases.filter((item) => item.approvalStatus === "APPROVED").length,
    rejected: cases.filter((item) => item.approvalStatus === "REJECTED").length,
  }), [cases]);

  function openDecision(item, type) {
    setDialog({ item, type });
    setAnalyst("");
    setComment("");
    setSubmitError("");
    setSuccess("");
  }

  async function submitDecision() {
    if (!dialog?.item?.incidentId || !dialog?.type || submitting) return;

    const analystName = analyst.trim();
    const note = comment.trim();

    if (!analystName) {
      setSubmitError("Analyst name is required.");
      return;
    }

    if (dialog.type === "REJECT" && !note) {
      setSubmitError("A rejection reason is required.");
      return;
    }

    setSubmitting(true);
    setSubmitError("");

    try {
      let result;

      if (dialog.type === "APPROVE") {
        result = await approveIncident(dialog.item.incidentId, {
          analyst: analystName,
          comment: note,
        });
      } else {
        result = await rejectIncident(dialog.item.incidentId, {
          analyst: analystName,
          reason: note,
        });
      }

      const action = dialog.type === "APPROVE" ? "approved" : "rejected";
      setSuccess(
        `Case ${dialog.item.incidentId} was ${action}. Backend status: ${text(result?.status)}. Real response executed: ${result?.real_response_executed === true ? "YES" : "NO"}.`
      );
      setDialog(null);
      await loadCases();
    } catch (requestError) {
      setSubmitError(apiError(requestError));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Box sx={{ pb: 4 }}>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        alignItems={{ xs: "flex-start", sm: "center" }}
        spacing={2}
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800 }}>
            Approvals
          </Typography>
          <Typography sx={{ color: "#94a3b8", mt: 0.5 }}>
            Analyst review of persisted SENTINEL-X response plans.
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={<RefreshRounded />}
          onClick={loadCases}
          disabled={loading || submitting}
        >
          Refresh
        </Button>
      </Stack>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", sm: "repeat(3,1fr)" },
          gap: 2,
          mb: 3,
        }}
      >
        <Metric label="Pending review" value={stats.pending} color="#f59e0b" />
        <Metric label="Approved" value={stats.approved} color="#22c55e" />
        <Metric label="Rejected" value={stats.rejected} color="#ef4444" />
      </Box>

      <Alert icon={<ShieldRounded />} severity="info" sx={{ mb: 3 }}>
        Approval is active for the <strong>simulation-only SOC workflow</strong>.
        Approving a case may route its persisted response action through the
        simulation handler, but the backend keeps real endpoint execution disabled.
      </Alert>

      {loading && (
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
          <CircularProgress size={22} />
          <Typography>Loading persisted SOC cases...</Typography>
        </Stack>
      )}

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}

      {!!warnings.length && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Some cases could not be loaded.
          {warnings.slice(0, 3).map((warning, index) => (
            <Typography key={index} sx={{ fontSize: 12 }}>
              {warning}
            </Typography>
          ))}
        </Alert>
      )}

      {!loading && !error && !cases.length && (
        <Card>
          <CardContent sx={{ p: 4, textAlign: "center" }}>
            <ApprovalRounded sx={{ fontSize: 38, color: "#64748b" }} />
            <Typography variant="h6" sx={{ mt: 1 }}>
              No persisted SOC approvals available
            </Typography>
            <Typography sx={{ color: "#94a3b8", mt: 1 }}>
              Run AI Investigation for a qualifying incident to create a
              simulation-only SOC workflow first.
            </Typography>
          </CardContent>
        </Card>
      )}

      <Stack spacing={2}>
        {cases.map((item) => (
          <CaseCard
            key={item.incidentId}
            item={item}
            onDecision={openDecision}
            onOpenSimulator={(incidentId) =>
              navigate("/response-simulator", { state: { incidentId } })
            }
            onOpenInvestigation={(incidentId) =>
              navigate("/ai-security", { state: { incidentId } })
            }
          />
        ))}
      </Stack>

      <Dialog
        open={Boolean(dialog)}
        onClose={() => !submitting && setDialog(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>
          {dialog?.type === "APPROVE"
            ? "Approve Simulation Workflow"
            : "Reject Response Plan"}
        </DialogTitle>

        <DialogContent>
          <Alert
            severity={dialog?.type === "APPROVE" ? "info" : "warning"}
            sx={{ mb: 2, mt: 1 }}
          >
            {dialog?.type === "APPROVE"
              ? "This approves the persisted SOC case and permits simulation-only response routing. It does not authorize a real endpoint action."
              : "Rejecting the case prevents the proposed response from being approved in this SOC workflow."}
          </Alert>

          <Typography sx={{ color: "#94a3b8", fontSize: 12, mb: 2 }}>
            Incident: {dialog?.item?.incidentId}
          </Typography>

          <TextField
            fullWidth
            label="Analyst name"
            value={analyst}
            onChange={(event) => setAnalyst(event.target.value)}
            disabled={submitting}
            sx={{ mb: 2 }}
          />

          <TextField
            fullWidth
            multiline
            minRows={3}
            label={dialog?.type === "APPROVE" ? "Comment (optional)" : "Rejection reason"}
            value={comment}
            onChange={(event) => setComment(event.target.value)}
            disabled={submitting}
          />

          {submitError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {submitError}
            </Alert>
          )}
        </DialogContent>

        <DialogActions>
          <Button onClick={() => setDialog(null)} disabled={submitting}>
            Cancel
          </Button>
          <Button
            variant="contained"
            color={dialog?.type === "APPROVE" ? "success" : "error"}
            onClick={submitDecision}
            disabled={submitting}
          >
            {submitting
              ? "Submitting..."
              : dialog?.type === "APPROVE"
                ? "Approve Simulation"
                : "Reject Plan"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
