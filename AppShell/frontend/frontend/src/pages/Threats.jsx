
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@mui/material";

import {
  ArrowForwardRounded,
  RefreshRounded,
  SearchRounded,
  ShieldRounded,
  WarningAmberRounded,
} from "@mui/icons-material";

import api, { getLiveDetections } from "../api/sentinelApi";

const REFRESH_MS = 10000;
const DETECTION_LIMIT = 100;
const INCIDENT_LIMIT = 1000;

const COLORS = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#3b82f6",
  INFO: "#94a3b8",
  UNKNOWN: "#94a3b8",
};

function display(value, fallback = "Not reported") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  return String(value);
}

function eventKey(value) {
  return String(value ?? "").trim().toLowerCase();
}

function formatTime(value) {
  if (!value) return "Not reported";

  if (
    typeof value === "string" &&
    !/[zZ]$|[+-]\d\d:\d\d$/.test(value)
  ) {
    return `${value} (timezone unspecified)`;
  }

  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? String(value)
    : parsed.toLocaleString();
}

function reasonsOf(value) {
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
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return reasonsOf(parsed);
    } catch {
      // A plain-text reason is valid.
    }
    return value ? [value.replace(/_/g, " ")] : [];
  }

  return [];
}

function modeOf(record) {
  const fields = [
    record?.detection_mode,
    record?.operating_mode,
    record?.mode,
    record?.process_evidence?.detection_mode,
  ];

  const reported = fields.find(
    (value) => typeof value === "string" && value.trim()
  );

  if (record?.simulation_mode === true) return "SIMULATION";

  return reported ? reported.toUpperCase() : null;
}

function makeIncidentIndex(incidents) {
  const index = new Map();

  for (const incident of incidents) {
    if (!Array.isArray(incident?.event_ids)) continue;

    for (const eventId of incident.event_ids) {
      const key = eventKey(eventId);
      if (!key) continue;

      const matches = index.get(key) || [];

      if (
        !matches.some(
          (item) =>
            String(item.incident_id) ===
            String(incident.incident_id)
        )
      ) {
        matches.push(incident);
      }

      index.set(key, matches);
    }
  }

  return index;
}

function normalizeDetection(record, incidentIndex) {
  const process = record.process_evidence || {};
  const matchingIncidents =
    incidentIndex.get(eventKey(record.event_id)) || [];

  const directIncidentId =
    record.incident_id === null ||
    record.incident_id === undefined ||
    record.incident_id === ""
      ? null
      : String(record.incident_id);

  const incidentIds = [
    ...new Set([
      ...matchingIncidents
        .map((item) => item.incident_id)
        .filter((id) => id !== null && id !== undefined)
        .map(String),
      ...(directIncidentId ? [directIncidentId] : []),
    ]),
  ];

  const processName =
    record.process_name || process.process_name || null;

  const severity = String(
    record.severity || "UNKNOWN"
  ).toUpperCase();

  const title =
    record.display_title ||
    (processName
      ? `Behavioral detection — ${processName}`
      : String(record.threat_type || "Security detection")
          .replace(/_/g, " "));

  return {
    ...record,
    id: `detection-${record.detection_id}`,
    title,
    processName,
    pid: record.pid ?? process.pid,
    severity,
    mode: modeOf(record),
    reasons: reasonsOf(
      record.detection_reason ?? process.fusion_reasons
    ),
    matchingIncidents,
    incidentIds,
    linked: incidentIds.length > 0,
  };
}

function Metric({ label, value, color }) {
  return (
    <Card>
      <CardContent sx={{ p: 2.5 }}>
        <Typography sx={{ color: "#94a3b8", fontSize: 13 }}>
          {label}
        </Typography>
        <Typography
          sx={{
            mt: 1,
            fontSize: 30,
            fontWeight: 800,
            color,
          }}
        >
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

function ThreatCard({ threat, linksComplete, onOpen }) {
  const color = COLORS[threat.severity] || COLORS.UNKNOWN;

  return (
    <Card
      sx={{
        border: `1px solid ${color}44`,
        "&:hover": { borderColor: color },
      }}
    >
      <CardContent sx={{ p: 2.5 }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          justifyContent="space-between"
          spacing={2}
        >
          <Box sx={{ minWidth: 0 }}>
            <Stack direction="row" alignItems="center" spacing={1}>
              <WarningAmberRounded sx={{ color }} />
              <Typography
                sx={{
                  fontSize: 17,
                  fontWeight: 750,
                  overflowWrap: "anywhere",
                }}
              >
                {threat.title}
              </Typography>
            </Stack>

            <Typography
              sx={{ color: "#94a3b8", fontSize: 12, mt: 1 }}
            >
              Detection #{display(threat.detection_id)}
              {" · "}
              {display(threat.engine)}
              {" · "}
              {formatTime(threat.timestamp)}
            </Typography>
          </Box>

          <Stack
            direction="row"
            spacing={1}
            flexWrap="wrap"
            useFlexGap
            alignItems="flex-start"
          >
            <Chip
              size="small"
              label={threat.severity}
              sx={{
                color,
                background: `${color}18`,
                border: `1px solid ${color}`,
              }}
            />

            {threat.mode && (
              <Chip
                size="small"
                variant="outlined"
                color={
                  threat.mode.includes("SHADOW") ||
                  threat.mode === "SIMULATION"
                    ? "warning"
                    : "default"
                }
                label={threat.mode}
              />
            )}

            <Chip
              size="small"
              variant="outlined"
              color={threat.linked ? "success" : "default"}
              label={
                threat.linked
                  ? "Incident reference found"
                  : "Link not verified"
              }
            />
          </Stack>
        </Stack>

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              sm: "repeat(2, minmax(0, 1fr))",
              lg: "repeat(4, minmax(0, 1fr))",
            },
            gap: 2,
            my: 2.5,
          }}
        >
          {[
            ["Device", threat.device_id],
            [
              "Process",
              threat.processName
                ? `${threat.processName} / PID ${display(threat.pid)}`
                : "Not attributed",
            ],
            ["Risk score", threat.risk_score],
            ["Event ID", threat.event_id],
          ].map(([label, value]) => (
            <Box
              key={label}
              sx={{
                background: "#0f172a",
                borderRadius: 2,
                p: 1.5,
                minWidth: 0,
              }}
            >
              <Typography
                sx={{ color: "#94a3b8", fontSize: 12 }}
              >
                {label}
              </Typography>
              <Typography
                sx={{
                  mt: 0.6,
                  fontSize: 13,
                  overflowWrap: "anywhere",
                }}
              >
                {display(value)}
              </Typography>
            </Box>
          ))}
        </Box>

        <Typography sx={{ fontSize: 13, fontWeight: 700 }}>
          Recorded evidence
        </Typography>
        <Typography
          sx={{
            color: "#cbd5e1",
            mt: 0.6,
            fontSize: 13,
            overflowWrap: "anywhere",
          }}
        >
          {threat.reasons.length
            ? threat.reasons.join(", ")
            : "No specific detection reason recorded."}
        </Typography>

        <Stack
          direction={{ xs: "column", sm: "row" }}
          justifyContent="space-between"
          alignItems={{ xs: "flex-start", sm: "center" }}
          spacing={2}
          sx={{ mt: 2.5 }}
        >
          <Box>
            <Typography sx={{ fontSize: 12, color: "#94a3b8" }}>
              Incident IDs:{" "}
              {threat.incidentIds.length
                ? threat.incidentIds.join(", ")
                : "Not verified"}
            </Typography>
            <Typography
              sx={{ fontSize: 11, color: "#64748b", mt: 0.5 }}
            >
              {threat.linked
                ? "A stored incident reference was found; investigation status is not implied."
                : linksComplete
                  ? "No relationship found in retrieved incident records."
                  : "Incident lookup is unavailable or incomplete."}
            </Typography>
          </Box>

          <Button
            endIcon={<ArrowForwardRounded />}
            variant="outlined"
            onClick={onOpen}
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

  const [detections, setDetections] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [storedCount, setStoredCount] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [incidentError, setIncidentError] = useState("");
  const [incidentTruncated, setIncidentTruncated] = useState(false);
  const [updated, setUpdated] = useState(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [engineFilter, setEngineFilter] = useState("ALL");
  const [linkFilter, setLinkFilter] = useState("ALL");

  const load = useCallback(async (initial = false) => {
    if (!initial) setRefreshing(true);

    try {
      const [detectionsResult, incidentsResult] =
        await Promise.allSettled([
          getLiveDetections(DETECTION_LIMIT),
          api.get("/detected-incidents", {
            params: { limit: INCIDENT_LIMIT },
          }),
        ]);

      if (detectionsResult.status === "fulfilled") {
        const result = detectionsResult.value || {};
        setDetections(
          Array.isArray(result.detections)
            ? result.detections
            : []
        );
        setStoredCount(result.total_stored_detections ?? null);
        setError("");
      } else {
        setError(
          detectionsResult.reason?.message ||
            "Could not retrieve detections."
        );
      }

      if (incidentsResult.status === "fulfilled") {
        const data = incidentsResult.value.data;
        const records = Array.isArray(data?.incidents)
          ? data.incidents
          : Array.isArray(data)
            ? data
            : [];

        setIncidents(records);
        setIncidentTruncated(records.length >= INCIDENT_LIMIT);
        setIncidentError("");
      } else {
        setIncidentError(
          incidentsResult.reason?.message ||
            "Could not retrieve incident records."
        );
      }

      setUpdated(new Date());
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    let busy = false;
    let mounted = true;

    async function refresh() {
      if (busy || !mounted) return;

      busy = true;
      try {
        if (mounted) await load();
      } finally {
        busy = false;
      }
    }

    refresh();
    const timer = setInterval(refresh, REFRESH_MS);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, [load]);

  const incidentIndex = useMemo(
    () => makeIncidentIndex(incidents),
    [incidents]
  );

  const threats = useMemo(
    () =>
      detections
        .filter(
          (item) =>
            item &&
            item.detection_id !== null &&
            item.detection_id !== undefined
        )
        .map((item) => normalizeDetection(item, incidentIndex)),
    [detections, incidentIndex]
  );

  const engines = useMemo(
    () =>
      [...new Set(threats.map((item) => item.engine).filter(Boolean))]
        .sort(),
    [threats]
  );

  const visibleThreats = useMemo(() => {
    const query = search.trim().toLowerCase();

    return threats.filter((threat) => {
      if (
        severityFilter !== "ALL" &&
        threat.severity !== severityFilter
      ) {
        return false;
      }

      if (
        engineFilter !== "ALL" &&
        threat.engine !== engineFilter
      ) {
        return false;
      }

      if (linkFilter === "LINKED" && !threat.linked) return false;
      if (linkFilter === "UNVERIFIED" && threat.linked) return false;

      if (!query) return true;

      return [
        threat.title,
        threat.engine,
        threat.event_id,
        threat.detection_id,
        threat.device_id,
        threat.processName,
        threat.pid,
        threat.threat_type,
        ...threat.incidentIds,
      ]
        .map((value) => String(value ?? "").toLowerCase())
        .some((value) => value.includes(query));
    });
  }, [threats, search, severityFilter, engineFilter, linkFilter]);

  const highCount = threats.filter(
    (item) =>
      item.severity === "HIGH" || item.severity === "CRITICAL"
  ).length;

  const linkedCount = threats.filter((item) => item.linked).length;

  const linksComplete = !incidentError && !incidentTruncated;

  return (
    <Box>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        spacing={2}
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 750 }}>
            Threats
          </Typography>
          <Typography sx={{ color: "#94a3b8", mt: 0.7 }}>
            Live endpoint detection records and supporting evidence
          </Typography>
          <Typography sx={{ color: "#64748b", fontSize: 12, mt: 0.5 }}>
            An anomaly is not automatically a confirmed attack.
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={
            refreshing ? (
              <CircularProgress size={16} />
            ) : (
              <RefreshRounded />
            )
          }
          disabled={refreshing}
          onClick={() => load()}
        >
          Refresh
        </Button>
      </Stack>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            md: "repeat(3, 1fr)",
          },
          gap: 2,
          mb: 3,
        }}
      >
        <Metric
          label="Recent high-priority detections"
          value={highCount}
          color="#f97316"
        />
        <Metric
          label="Recent detections with incident references"
          value={linkedCount}
          color="#22c55e"
        />
        <Metric
          label="Total stored detections"
          value={storedCount ?? "—"}
          color="#60a5fa"
        />
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Stack
            direction={{ xs: "column", md: "row" }}
            spacing={2}
          >
            <TextField
              label="Search detections"
              placeholder="Process, device, engine, event ID..."
              size="small"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              InputProps={{
                startAdornment: (
                  <SearchRounded sx={{ mr: 1, color: "#94a3b8" }} />
                ),
              }}
              sx={{ flex: 2 }}
            />

            <FormControl size="small" sx={{ minWidth: 130, flex: 1 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                label="Severity"
                value={severityFilter}
                onChange={(event) =>
                  setSeverityFilter(event.target.value)
                }
              >
                <MenuItem value="ALL">All</MenuItem>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].map(
                  (severity) => (
                    <MenuItem key={severity} value={severity}>
                      {severity}
                    </MenuItem>
                  )
                )}
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 130, flex: 1 }}>
              <InputLabel>Engine</InputLabel>
              <Select
                label="Engine"
                value={engineFilter}
                onChange={(event) =>
                  setEngineFilter(event.target.value)
                }
              >
                <MenuItem value="ALL">All</MenuItem>
                {engines.map((engine) => (
                  <MenuItem key={engine} value={engine}>
                    {engine}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 150, flex: 1 }}>
              <InputLabel>Incident link</InputLabel>
              <Select
                label="Incident link"
                value={linkFilter}
                onChange={(event) =>
                  setLinkFilter(event.target.value)
                }
              >
                <MenuItem value="ALL">All</MenuItem>
                <MenuItem value="LINKED">Reference found</MenuItem>
                <MenuItem value="UNVERIFIED">Not verified</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </CardContent>
      </Card>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Detection API error: {error}. Existing results may be stale.
        </Alert>
      )}

      {incidentError && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Incident lookup unavailable: {incidentError}
        </Alert>
      )}

      {incidentTruncated && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Incident lookup reached its 1,000-record limit.
          Unmatched detections may have older incident references.
        </Alert>
      )}

      {loading && (
        <Box sx={{ textAlign: "center", py: 5 }}>
          <CircularProgress />
        </Box>
      )}

      {!loading && !visibleThreats.length && (
        <Alert severity="info">
          No recent detection records match your filters.
        </Alert>
      )}

      <Stack spacing={2}>
        {visibleThreats.map((threat) => (
          <ThreatCard
            key={threat.id}
            threat={threat}
            linksComplete={linksComplete}
            onOpen={() =>
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

      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        spacing={1}
        sx={{ mt: 3 }}
      >
        <Typography sx={{ color: "#64748b", fontSize: 12 }}>
          Showing {visibleThreats.length} of {threats.length} recent
          detections (maximum {DETECTION_LIMIT}).
          Filters apply to retrieved records only.
        </Typography>

        <Typography sx={{ color: "#64748b", fontSize: 12 }}>
          Auto-refresh: 10 seconds
          {updated ? ` · Last updated: ${updated.toLocaleTimeString()}` : ""}
        </Typography>
      </Stack>
    </Box>
  );
}
