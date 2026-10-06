import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  LinearProgress,
  Stack,
  Tab,
  Tabs,
  Typography,
} from "@mui/material";

import {
  ArrowForwardRounded,
  AccessTimeRounded,
  DevicesRounded,
  PsychologyRounded,
  ShieldRounded,
  WarningAmberRounded,
} from "@mui/icons-material";

import api, {
  getLiveDetections,
} from "../api/sentinelApi";

const REFRESH_MS = 10000;
const DETECTION_LIMIT = 100;
const INCIDENT_LIMIT = 1000;

const severityColor = (severity) => {
  switch (String(severity || "").toUpperCase()) {
    case "CRITICAL": return "#ef4444";
    case "HIGH": return "#f97316";
    case "MEDIUM": return "#f59e0b";
    case "LOW": return "#3b82f6";
    default: return "#94a3b8";
  }
};

function valueOrFallback(value, fallback = "Not reported") {
  return value === null || value === undefined || value === ""
    ? fallback
    : String(value);
}

function formatTime(timestamp) {
  if (!timestamp) return "Not reported";

  // SQLite historically stores some timestamps without a timezone.
  // Do not silently assume those values are UTC or local time.
  const parsed = new Date(timestamp);

  if (Number.isNaN(parsed.getTime())) {
    return String(timestamp);
  }

  if (
    typeof timestamp === "string" &&
    !/[zZ]$|[+-]\d\d:\d\d$/.test(timestamp)
  ) {
    return String(timestamp) + " (timezone unspecified)";
  }

  return parsed.toLocaleString();
}

function eventKey(value) {
  return String(value ?? "").trim().toLowerCase();
}

function titleCaseThreat(value) {
  const text = String(value || "Security detection")
    .replace(/_/g, " ")
    .trim();

  return text.replace(/\b\w/g, (character) =>
    character.toUpperCase()
  );
}

function buildDetectionScores(record, process) {
  const stored = record.model_scores || {};

  return {
    ...stored,

    rule_score:
      stored.rule_score ??
      process.rule_score ??
      process.behavior_score ??
      null,

    statistical_score:
      stored.statistical_score ??
      process.statistical_score ??
      null,

    isolation_forest_score:
      stored.isolation_forest_score ??
      process.isolation_forest?.anomaly_confidence ??
      null,

    autoencoder_score:
      stored.autoencoder_score ??
      process.autoencoder?.anomaly_confidence ??
      null,

    temporal_score:
      stored.temporal_score ??
      process.temporal?.score ??
      null,

    fusion_score:
      stored.fusion_score ??
      process.fusion_score ??
      record.risk_score ??
      null,

    independent_signal_count:
      stored.independent_signal_count ??
      record.independent_signal_count ??
      null,
  };
}

function displayReasons(value) {
  if (Array.isArray(value)) {
    return value
      .filter(Boolean)
      .map((item) =>
        typeof item === "string"
          ? item.replace(/_/g, " ")
          : JSON.stringify(item)
      );
  }

  if (typeof value === "string") {
    try {
      const decoded = JSON.parse(value);
      if (Array.isArray(decoded)) return displayReasons(decoded);
    } catch {
      // Treat as plain text.
    }

    return value ? [value.replace(/_/g, " ")] : [];
  }

  return [];
}

function modelFlag(model) {
  if (!model || model.available !== true) {
    return "Not available";
  }
  return valueOrFallback(model.anomaly_label, "Reported");
}

async function fetchIncidentRecords() {
  const response = await api.get("/detected-incidents", {
    params: { limit: INCIDENT_LIMIT },
  });

  const data = response.data || {};

  const incidents = Array.isArray(data.incidents)
    ? data.incidents
    : Array.isArray(data)
      ? data
      : [];

  return {
    incidents,
    potentiallyTruncated: incidents.length >= INCIDENT_LIMIT,
  };
}

function createIncidentIndex(incidents) {
  const index = new Map();

  for (const incident of incidents) {
    if (!incident || !Array.isArray(incident.event_ids)) {
      continue;
    }

    for (const id of incident.event_ids) {
      const key = eventKey(id);
      if (!key) continue;

      const existing = index.get(key) || [];

      if (
        !existing.some(
          (item) => item.incident_id === incident.incident_id
        )
      ) {
        existing.push(incident);
      }

      index.set(key, existing);
    }
  }

  return index;
}

function normalizeDetection(record, incidentIndex) {
  const process = record.process_evidence || {};
  const scores = buildDetectionScores(record, process);

  const matchingIncidents =
    incidentIndex.get(eventKey(record.event_id)) || [];

  const directIncidentId = record.incident_id
    ? String(record.incident_id)
    : null;

  const incidentIds = [
    ...new Set([
      ...matchingIncidents
        .map((item) => item.incident_id)
        .filter(Boolean)
        .map(String),
      ...(directIncidentId ? [directIncidentId] : []),
    ]),
  ];

  const name =
    record.process_name ||
    process.process_name ||
    null;

  const threatLabel = titleCaseThreat(
    record.threat_type || "Security detection"
  );

  const title =
    record.display_title ||
    (name
      ? `${threatLabel} - ${name}`
      : threatLabel);

  return {
    ...record,
    id: `detection-${record.detection_id}`,
    title,
    processName: name,
    pid: record.pid ?? process.pid,
    parentName:
      record.parent_process_name ??
      process.parent_process_name,
    deviceId: record.device_id,
    severity: String(record.severity || "UNKNOWN").toUpperCase(),
    reasons: displayReasons(
      record.detection_reason ?? process.fusion_reasons
    ),
    scores,
    process,
    matchingIncidents,
    incidentIds,
    linked: incidentIds.length > 0,
  };
}

function InfoItem({ icon, label, value }) {
  return (
    <Box
      sx={{
        p: 1.7,
        background: "#0f172a",
        border: "1px solid #1e293b",
        borderRadius: 2,
        minWidth: 0,
      }}
    >
      <Stack direction="row" spacing={1} alignItems="center">
        {icon}
        <Typography sx={{ color: "#94a3b8", fontSize: 12 }}>
          {label}
        </Typography>
      </Stack>

      <Typography
        sx={{
          mt: 0.8,
          fontSize: 14,
          fontWeight: 650,
          overflowWrap: "anywhere",
        }}
      >
        {valueOrFallback(value)}
      </Typography>
    </Box>
  );
}

function SummaryCard({ title, count, color }) {
  return (
    <Card>
      <CardContent sx={{ p: 2.5 }}>
        <Typography sx={{ color: "#94a3b8", fontSize: 13 }}>
          {title}
        </Typography>

        <Typography
          sx={{
            fontSize: 29,
            fontWeight: 800,
            color,
            mt: 0.5,
          }}
        >
          {count}
        </Typography>
      </CardContent>
    </Card>
  );
}

function ThreatCard({ threat, onView, linksComplete }) {
  const color = severityColor(threat.severity);

  const isolationForest = threat.process.isolation_forest;
  const autoencoder = threat.process.autoencoder;

  const reason =
    threat.reasons.length > 0
      ? threat.reasons.join(", ")
      : "No specific detection reason provided";

  return (
    <Card
      sx={{
        borderColor: `${color}55`,
        "&:hover": { borderColor: color },
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          justifyContent="space-between"
          alignItems={{ xs: "flex-start", md: "center" }}
          spacing={2}
        >
          <Stack direction="row" spacing={2}>
            <Box
              sx={{
                width: 46,
                height: 46,
                borderRadius: 2,
                background: `${color}18`,
                color,
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
              }}
            >
              <WarningAmberRounded />
            </Box>

            <Box>
              <Typography
                sx={{
                  fontWeight: 750,
                  fontSize: 18,
                  overflowWrap: "anywhere",
                }}
              >
                {threat.title}
              </Typography>

              <Typography
                sx={{
                  color: "#94a3b8",
                  fontSize: 12,
                  mt: 0.5,
                }}
              >
                Detection #{threat.detection_id}
                {" | "}
                {valueOrFallback(threat.engine)}
              </Typography>
            </Box>
          </Stack>

          <Stack direction="row" spacing={1} flexWrap="wrap">
            <Chip
              label={threat.severity}
              size="small"
              sx={{
                color,
                border: `1px solid ${color}`,
                background: `${color}18`,
              }}
            />

            <Chip
              label={
                threat.linked
                  ? "Incident Linked"
                  : "Link Not Verified"
              }
              size="small"
              color={threat.linked ? "success" : "default"}
              variant="outlined"
            />
          </Stack>
        </Stack>

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              sm: "repeat(2, minmax(0,1fr))",
              lg: "repeat(4, minmax(0,1fr))",
            },
            gap: 1.5,
            mt: 3,
          }}
        >
          <InfoItem
            icon={<DevicesRounded fontSize="small" />}
            label="Process / PID"
            value={
              threat.processName
                ? `${threat.processName} / ${valueOrFallback(threat.pid)}`
                : "Process not reported"
            }
          />

          <InfoItem
            icon={<ShieldRounded fontSize="small" />}
            label="Risk Score"
            value={
              threat.risk_score == null
                ? "Not reported"
                : `${threat.risk_score}/100`
            }
          />

          <InfoItem
            icon={<PsychologyRounded fontSize="small" />}
            label="Fusion Confidence"
            value={
              threat.process.fusion_confidence ??
              threat.scores.evidence_confidence ??
              "Not reported"
            }
          />

          <InfoItem
            icon={<AccessTimeRounded fontSize="small" />}
            label="Detected"
            value={formatTime(threat.timestamp)}
          />
        </Box>

        <Box sx={{ mt: 2 }}>
          <Typography
            sx={{ fontWeight: 700, fontSize: 13, mb: 0.7 }}
          >
            Recorded detection reason
          </Typography>

          <Typography
            sx={{
              fontSize: 13,
              color: "#cbd5e1",
              overflowWrap: "anywhere",
            }}
          >
            {reason}
          </Typography>
        </Box>

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              sm: "1fr 1fr",
            },
            gap: 2,
            mt: 2,
          }}
        >
          <Box>
            <Typography
              sx={{ fontSize: 12, color: "#94a3b8", mb: 0.6 }}
            >
              Isolation Forest
            </Typography>
            <Typography sx={{ fontSize: 13 }}>
              {modelFlag(isolationForest)}
            </Typography>
          </Box>

          <Box>
            <Typography
              sx={{ fontSize: 12, color: "#94a3b8", mb: 0.6 }}
            >
              Autoencoder
            </Typography>
            <Typography sx={{ fontSize: 13 }}>
              {modelFlag(autoencoder)}
            </Typography>
          </Box>
        </Box>

        <Divider sx={{ my: 2 }} />

        <Stack
          direction={{ xs: "column", sm: "row" }}
          alignItems={{ xs: "stretch", sm: "center" }}
          justifyContent="space-between"
          spacing={2}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography
              sx={{ fontSize: 12, color: "#94a3b8" }}
            >
              Incident:
              {" "}
              {threat.incidentIds.length
                ? threat.incidentIds.join(", ")
                : "Link not verified"}
            </Typography>

            <Typography
              sx={{ fontSize: 11, color: "#64748b", mt: 0.5 }}
            >
              {threat.linked
                ? "Linked through a recorded incident ID or shared event ID."
                : linksComplete
                  ? "No link found in the retrieved incident records."
                  : "Incident lookup is incomplete or unavailable."}
            </Typography>
          </Box>

          <Button
            variant="outlined"
            endIcon={<ArrowForwardRounded />}
            onClick={onView}
            sx={{ flexShrink: 0 }}
          >
            View Threat
          </Button>
        </Stack>
      </CardContent>
    </Card>
  );
}

export default function Threats() {
  const navigate = useNavigate();

  const [tab, setTab] = useState("ALL");
  const [detections, setDetections] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [storedCount, setStoredCount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [incidentError, setIncidentError] = useState("");
  const [incidentTruncated, setIncidentTruncated] = useState(false);
  const [updated, setUpdated] = useState(null);

  useEffect(() => {
    let active = true;
    let busy = false;

    async function load() {
      if (busy) return;
      busy = true;

      try {
        const [detResult, incResult] = await Promise.allSettled([
          getLiveDetections(DETECTION_LIMIT),
          fetchIncidentRecords(),
        ]);

        if (!active) return;

        if (detResult.status === "fulfilled") {
          const response = detResult.value || {};

          setDetections(
            Array.isArray(response.detections)
              ? response.detections
              : []
          );
          setStoredCount(response.total_stored_detections ?? null);
          setError("");
        } else {
          setError(
            detResult.reason?.message ||
            "Unable to retrieve recent detections."
          );
        }

        if (incResult.status === "fulfilled") {
          setIncidents(incResult.value.incidents);
          setIncidentTruncated(incResult.value.potentiallyTruncated);
          setIncidentError("");
        } else {
          setIncidentError(
            incResult.reason?.message ||
            "Incident links could not be refreshed."
          );
        }

        setUpdated(new Date());
      } finally {
        busy = false;
        if (active) setLoading(false);
      }
    }

    load();
    const interval = setInterval(load, REFRESH_MS);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  const incidentIndex = useMemo(
    () => createIncidentIndex(incidents),
    [incidents]
  );

  const threats = useMemo(
    () =>
      detections
        .filter(
          (record) =>
            record &&
            record.detection_id !== null &&
            record.detection_id !== undefined
        )
        .map((record) => normalizeDetection(record, incidentIndex)),
    [detections, incidentIndex]
  );

  const displayed = useMemo(() => {
    if (tab === "HIGH") {
      return threats.filter(
        (t) => t.severity === "HIGH" || t.severity === "CRITICAL"
      );
    }
    if (tab === "LINKED") return threats.filter((t) => t.linked);
    if (tab === "UNVERIFIED") return threats.filter((t) => !t.linked);
    return threats;
  }, [threats, tab]);

  const highCount = threats.filter(
    (t) => t.severity === "HIGH" || t.severity === "CRITICAL"
  ).length;

  const linkedCount = threats.filter((t) => t.linked).length;
  const linksComplete = !incidentError && !incidentTruncated;

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 750 }}>
          Threats
        </Typography>

        <Typography sx={{ color: "#94a3b8", mt: 0.5 }}>
          Live endpoint detections and recorded security evidence
        </Typography>

        <Typography
          sx={{ color: "#64748b", mt: 0.6, fontSize: 12 }}
        >
          An anomaly alert is not automatically a confirmed attack.
        </Typography>
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            md: "repeat(3,1fr)",
          },
          gap: 2,
          mb: 3,
        }}
      >
        <SummaryCard
          title="Recent High-Priority Detections"
          count={highCount}
          color="#f97316"
        />
        <SummaryCard
          title="Recent Incident-Linked Detections"
          count={linkedCount}
          color="#22c55e"
        />
        <SummaryCard
          title="Total Stored Detections"
          count={storedCount ?? "—"}
          color="#60a5fa"
        />
      </Box>

      <Card sx={{ mb: 2 }}>
        <Tabs
          value={tab}
          onChange={(_, next) => setTab(next)}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab value="ALL" label="All" />
          <Tab value="HIGH" label="High Priority" />
          <Tab value="LINKED" label="Incident Linked" />
          <Tab value="UNVERIFIED" label="Link Not Verified" />
        </Tabs>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {incidentError && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Incident lookup: {incidentError}
        </Alert>
      )}

      {incidentTruncated && (
        <Alert severity="info" sx={{ mb: 2 }}>
          The incident lookup reached its 1,000-record limit.
          Unmatched detections may still belong to older incidents.
        </Alert>
      )}

      {loading && (
        <Box sx={{ py: 5, textAlign: "center" }}>
          <CircularProgress />
        </Box>
      )}

      {!loading && !displayed.length && (
        <Alert severity="info">
          No recent detections match this filter.
        </Alert>
      )}

      <Stack spacing={2}>
        {displayed.map((threat) => (
          <ThreatCard
            key={threat.id}
            threat={threat}
            linksComplete={linksComplete}
            onView={() =>
              navigate(`/threats/${threat.id}`, {
                state: {
                  detection: threat,
                  incident: threat.matchingIncidents[0] || null,
                  incidentIds: threat.incidentIds,
                },
              })
            }
          />
        ))}
      </Stack>

      <Typography
        sx={{ color: "#64748b", fontSize: 12, mt: 3 }}
      >
        Showing up to 100 recent detections; refreshes every
        10 seconds.
        {updated ? ` Last updated: ${updated.toLocaleTimeString()}.` : ""}
      </Typography>
    </Box>
  );
}