
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Alert, Box, Button, Card, CardContent, Chip,
  CircularProgress, Divider, Stack, Typography,
} from "@mui/material";
import {
  ApprovalRounded, WarningAmberRounded,
  CheckCircleRounded, CancelRounded, ShieldRounded,
  StopCircleRounded, LanguageRounded, FolderRounded,
  SettingsRounded, DevicesRounded, RefreshRounded,
} from "@mui/icons-material";
import api from "../api/sentinelApi";

function obj(value) {
  return value && typeof value === "object" &&
    !Array.isArray(value) ? value : {};
}

function arr(value) {
  return Array.isArray(value) ? value : [];
}

function valueText(value, fallback = "Not available") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function errorText(error) {
  const detail = error?.response?.data?.detail;
  return typeof detail === "string"
    ? detail
    : error?.message || "Request failed";
}

function normalizedStatus(status) {
  const raw = String(status || "UNKNOWN").toUpperCase();
  if (raw.includes("REJECT")) return "REJECTED";
  if (raw.includes("APPROV")) return "APPROVED";
  if (
    raw.includes("PENDING") ||
    raw.includes("AWAIT") ||
    raw.includes("REVIEW")
  ) return "PENDING";
  return raw;
}

function actionIcon(type) {
  switch (String(type).toUpperCase()) {
    case "TERMINATE_PROCESS":
      return <StopCircleRounded />;
    case "QUARANTINE_FILE":
      return <FolderRounded />;
    case "BLOCK_NETWORK":
      return <LanguageRounded />;
    case "REMEDIATE_PERSISTENCE":
      return <SettingsRounded />;
    case "ISOLATE_ENDPOINT":
      return <DevicesRounded />;
    default:
      return <ApprovalRounded />;
  }
}

function statusColor(status) {
  if (status === "APPROVED") return "#22c55e";
  if (status === "REJECTED") return "#ef4444";
  if (status === "PENDING") return "#f59e0b";
  return "#94a3b8";
}

function impactColor(impact) {
  const name = String(impact || "").toUpperCase();
  if (name === "HIGH") return "#ef4444";
  if (name === "MEDIUM") return "#f59e0b";
  if (name === "LOW") return "#22c55e";
  return "#94a3b8";
}

function SummaryCard({ title, count, color }) {
  return (
    <Card>
      <CardContent sx={{ p: 2.5 }}>
        <Typography sx={{ color: "#64748b", fontSize: 13 }}>
          {title}
        </Typography>
        <Typography
          sx={{ fontSize: 30, fontWeight: 800, mt: 0.5, color }}
        >
          {count}
        </Typography>
      </CardContent>
    </Card>
  );
}

function InfoBox({ label, value, color }) {
  return (
    <Box
      sx={{
        p: 1.5, borderRadius: "10px",
        background: "#0f172a",
        border: "1px solid #1e293b",
      }}
    >
      <Typography sx={{ color: "#64748b", fontSize: 11 }}>
        {label}
      </Typography>
      <Typography
        sx={{
          color: color || "#f8fafc", fontSize: 13,
          fontWeight: 600, mt: 0.5,
          overflowWrap: "anywhere",
        }}
      >
        {valueText(value)}
      </Typography>
    </Box>
  );
}

/*
  Normalize persisted records only. Never create an action
  from a Digital Twin hypothetical preview.
*/
function normalizeAction(source, incidentId, position) {
  const action = obj(source);
  const details = obj(action.action);
  const target = action.target ?? details.target;
  const targetString =
    target && typeof target === "object"
      ? "[Structured target stored in SOC case]"
      : valueText(target);

  const type = String(
    action.action_type ||
    details.action_type ||
    action.type ||
    "UNKNOWN"
  ).toUpperCase();

  const approval = obj(action.approval);

  const rawStatus =
    approval.status ||
    action.approval_status ||
    action.status ||
    "UNKNOWN";

  return {
    id: String(
      action.action_id ||
      action.id ||
      `${incidentId}-ACTION-${position + 1}`
    ),
    incidentId: String(incidentId),
    type,
    title: type.replaceAll("_", " "),
    description:
      action.description ||
      action.reason ||
      "Persisted SOC response-action record.",
    target: targetString,
    impact:
      String(
        action.operational_impact?.impact_level ||
        action.impact ||
        "UNKNOWN"
      ).toUpperCase(),
    severity: String(action.severity || "UNSPECIFIED"),
    reason:
      action.reason ||
      "See the linked SOC case for supporting evidence.",
    status: normalizedStatus(rawStatus),
    persistedApprovalStatus:
      approval.status || action.approval_status || null,
    source: "PERSISTED_SOC_CASE",
  };
}

function ApprovalCard({ action, onOpenCase }) {
  const status = action.status;
  const color = statusColor(status);

  return (
    <Card
      sx={{
        borderColor:
          status === "PENDING"
            ? "rgba(245,158,11,0.25)"
            : "#1e293b",
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          justifyContent="space-between"
          spacing={3}
        >
          <Stack
            direction="row"
            spacing={2}
            alignItems="flex-start"
            sx={{ flex: 1, minWidth: 0 }}
          >
            <Box
              sx={{
                width: 50, height: 50, minWidth: 50,
                borderRadius: "14px", display: "grid",
                placeItems: "center", color,
                background: `${color}12`,
              }}
            >
              {actionIcon(action.type)}
            </Box>

            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Stack
                direction="row"
                gap={1}
                flexWrap="wrap"
                alignItems="center"
                sx={{ mb: 1 }}
              >
                <Typography sx={{ fontSize: 18, fontWeight: 700 }}>
                  {action.title}
                </Typography>
                <Chip size="small" label={action.severity} />
              </Stack>

              <Typography
                sx={{ color: "#94a3b8", fontSize: 13 }}
              >
                {action.description}
              </Typography>

              <Typography
                sx={{
                  color: "#64748b", fontSize: 11,
                  mt: 1, overflowWrap: "anywhere",
                }}
              >
                Incident: {action.incidentId}
              </Typography>

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    md: "repeat(3,1fr)",
                  },
                  gap: 1.5,
                  mt: 2,
                }}
              >
                <InfoBox label="Target" value={action.target} />
                <InfoBox
                  label="Impact"
                  value={action.impact}
                  color={impactColor(action.impact)}
                />
                <InfoBox
                  label="Approval state"
                  value={action.persistedApprovalStatus}
                />
              </Box>

              <Box
                sx={{
                  mt: 2, p: 1.5,
                  borderRadius: "10px",
                  background: "#0f172a",
                }}
              >
                <Typography
                  sx={{ color: "#64748b", fontSize: 11 }}
                >
                  Recorded justification
                </Typography>
                <Typography
                  sx={{
                    color: "#cbd5e1",
                    fontSize: 13,
                    mt: 0.4,
                  }}
                >
                  {action.reason}
                </Typography>
              </Box>
            </Box>
          </Stack>

          <Stack
            alignItems={{
              xs: "stretch",
              md: "flex-end",
            }}
            spacing={1.5}
          >
            <Chip
              label={status}
              sx={{
                color,
                background: `${color}12`,
                border: `1px solid ${color}30`,
                fontWeight: 700,
              }}
            />
            {status === "PENDING" && (
              <Stack direction="row" spacing={1}>
                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<CancelRounded />}
                  disabled
                >
                  Reject
                </Button>
                <Button
                  variant="contained"
                  color="success"
                  startIcon={<CheckCircleRounded />}
                  disabled
                >
                  Approve
                </Button>
              </Stack>
            )}
            <Button
              size="small"
              variant="outlined"
              onClick={() => onOpenCase(action.incidentId)}
            >
              View Incident
            </Button>
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
}

export default function Approvals() {
  const navigate = useNavigate();

  const [actions, setActions] = useState([]);
  const [caseCount, setCaseCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [warnings, setWarnings] = useState([]);

  const loadApprovals = useCallback(async () => {
    setLoading(true);
    setError("");
    setWarnings([]);

    try {
      const response = await api.get("/cases", {
        params: { limit: 1000 },
      });

      if (!Array.isArray(response.data?.cases)) {
        throw new Error(
          "GET /cases did not return the expected cases array."
        );
      }

      const cases = response.data.cases;
      setCaseCount(cases.length);

      const loaded = [];
      const failures = [];

      /*
        Sequential reads avoid sending a burst of requests
        to the SOC backend. All operations are GET.
      */
      for (const entry of cases) {
        const incidentId = String(
          entry?.incident_id || entry?.id || ""
        );

        if (!incidentId) {
          failures.push("A case has no incident ID.");
          continue;
        }

        try {
          const details = await api.get(
            `/cases/${encodeURIComponent(incidentId)}`
          );

          const caseRecord = obj(details.data);
          let sourceActions = arr(caseRecord.response_actions);

          if (!sourceActions.length) {
            const result = await api.get(
              `/cases/${encodeURIComponent(incidentId)}/responses`
            );

            const body = result.data;
            sourceActions = Array.isArray(body)
              ? body
              : arr(body?.actions).length
                ? body.actions
                : arr(body?.response_actions);
          }

          sourceActions.forEach((item, index) => {
            if (item && typeof item === "object") {
              loaded.push(
                normalizeAction(item, incidentId, index)
              );
            }
          });
        } catch (requestError) {
          failures.push(
            `${incidentId}: ${errorText(requestError)}`
          );
        }
      }

      setActions(loaded);
      setWarnings(failures);
    } catch (requestError) {
      setActions([]);
      setCaseCount(0);
      setError(errorText(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadApprovals();
  }, [loadApprovals]);

  const stats = useMemo(() => ({
    pending: actions.filter((a) => a.status === "PENDING").length,
    approved: actions.filter((a) => a.status === "APPROVED").length,
    rejected: actions.filter((a) => a.status === "REJECTED").length,
  }), [actions]);

  return (
    <Box sx={{ pb: 4 }}>
      {/* HEADER */}
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        spacing={2}
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4">Approvals</Typography>
          <Typography
            sx={{ color: "#94a3b8", mt: 0.5 }}
          >
            Review only persisted SOC response actions.
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={<RefreshRounded />}
          onClick={loadApprovals}
          disabled={loading}
        >
          Refresh
        </Button>
      </Stack>

      {/* SUMMARY */}
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            sm: "repeat(3,1fr)",
          },
          gap: 2,
          mb: 3,
        }}
      >
        <SummaryCard
          title="Needs Your Review"
          count={stats.pending}
          color="#f59e0b"
        />
        <SummaryCard
          title="Approved"
          count={stats.approved}
          color="#22c55e"
        />
        <SummaryCard
          title="Rejected"
          count={stats.rejected}
          color="#ef4444"
        />
      </Box>

      {/* SAFETY BANNER */}
      <Card
        sx={{
          mb: 3,
          borderColor: "rgba(59,130,246,0.25)",
        }}
      >
        <CardContent
          sx={{
            display: "flex", gap: 2,
            alignItems: "center", p: 2.5,
          }}
        >
          <ShieldRounded sx={{ color: "#3b82f6" }} />
          <Box>
            <Typography fontWeight={600}>
              Simulation Mode Active
            </Typography>
            <Typography
              sx={{
                color: "#64748b",
                fontSize: 13, mt: 0.3,
              }}
            >
              Approval submission is locked during validation.
              This page reads stored SOC case records only.
              No process, file, network or device is modified.
            </Typography>
          </Box>
        </CardContent>
      </Card>

      {loading && (
        <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
          <CircularProgress size={22} />
          <Typography>Loading persisted SOC cases...</Typography>
        </Stack>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {!!warnings.length && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Some case records could not be loaded.
          {warnings.slice(0, 3).map((text, index) => (
            <Typography key={index} fontSize={12}>
              {text}
            </Typography>
          ))}
        </Alert>
      )}

      <Typography
        sx={{ color: "#94a3b8", fontSize: 12, mb: 2 }}
      >
        Persisted SOC cases: {caseCount} | Loaded response
        records: {actions.length}
      </Typography>

      {!loading && !error && !actions.length && (
        <Card>
          <CardContent sx={{ p: 4, textAlign: "center" }}>
            <WarningAmberRounded
              sx={{ color: "#f59e0b", fontSize: 36 }}
            />
            <Typography variant="h6" sx={{ mt: 1 }}>
              No persisted approval actions available
            </Typography>
            <Typography
              sx={{
                color: "#94a3b8",
                mt: 1,
              }}
            >
              This is not a simulated list of pending actions.
              A valid SOC case must exist before actual response
              actions can appear here.
            </Typography>
          </CardContent>
        </Card>
      )}

      <Stack spacing={2}>
        {actions.map((action, index) => (
          <ApprovalCard
            key={`${action.incidentId}-${action.id}-${index}`}
            action={action}
            onOpenCase={(id) =>
              navigate(`/incidents/${encodeURIComponent(id)}`)
            }
          />
        ))}
      </Stack>

      <Divider sx={{ my: 3 }} />

      <Alert severity="info">
        Approval and rejection buttons are intentionally disabled.
        We have not yet validated a backend operation that
        securely persists those decisions with authorization,
        evidence checks and audit logging.
      </Alert>
    </Box>
  );
}
