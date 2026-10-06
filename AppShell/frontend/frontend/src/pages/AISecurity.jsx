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
  Divider,
  FormControl,
  InputLabel,
  LinearProgress,
  MenuItem,
  Select,
  Stack,
  Typography,
} from "@mui/material";

import {
  ArrowForwardRounded,
  CheckCircleRounded,
  PsychologyRounded,
  RefreshRounded,
  ScienceRounded,
  SearchRounded,
  ShieldRounded,
  TimelineRounded,
  WarningAmberRounded,
} from "@mui/icons-material";

import api from "../api/sentinelApi";

const show = (value, fallback = "Not reported") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
};

const list = (value) => (Array.isArray(value) ? value : []);
const object = (value) => (
  value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {}
);

function riskColor(level) {
  switch (String(level || "").toUpperCase()) {
    case "CRITICAL": return "#ef4444";
    case "HIGH": return "#f97316";
    case "MEDIUM": return "#f59e0b";
    case "LOW": return "#3b82f6";
    default: return "#94a3b8";
  }
}

function MetricCard({ label, value, subtext, color = "#60a5fa" }) {
  return (
    <Card>
      <CardContent sx={{ p: 2.5 }}>
        <Typography sx={{ color: "#94a3b8", fontSize: 12 }}>
          {label}
        </Typography>
        <Typography sx={{ fontSize: 28, fontWeight: 800, color, mt: 0.7 }}>
          {show(value, "—")}
        </Typography>
        {subtext && (
          <Typography sx={{ color: "#64748b", fontSize: 11, mt: 0.8 }}>
            {subtext}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function DecisionCard({ decision }) {
  const severity = String(decision?.severity || "INFO").toUpperCase();
  const color = riskColor(severity);

  return (
    <Card variant="outlined" sx={{ borderColor: `${color}55` }}>
      <CardContent sx={{ p: 2.4 }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          justifyContent="space-between"
          spacing={1.2}
        >
          <Box>
            <Typography sx={{ fontWeight: 750 }}>
              {show(decision?.agent, "Agent")}
            </Typography>
            <Typography sx={{ color: "#94a3b8", fontSize: 12, mt: 0.5 }}>
              {show(decision?.decision)}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1}>
            <Chip label={severity} size="small" variant="outlined" sx={{ color }} />
            <Chip
              label={`Confidence ${show(decision?.confidence, "uncalibrated")}`}
              size="small"
              variant="outlined"
            />
          </Stack>
        </Stack>

        <Typography sx={{ mt: 1.5, color: "#cbd5e1", lineHeight: 1.65 }}>
          {show(decision?.reason, "No decision explanation reported.")}
        </Typography>
      </CardContent>
    </Card>
  );
}

function FindingList({ findings }) {
  if (!findings.length) {
    return <Alert severity="info">No investigation findings were returned.</Alert>;
  }

  return (
    <Stack spacing={1.2}>
      {findings.map((item, index) => (
        <Box
          key={index}
          sx={{
            p: 1.6,
            borderRadius: 2,
            background: "#0f172a",
            border: "1px solid #1e293b",
          }}
        >
          <Typography sx={{ color: "#cbd5e1", lineHeight: 1.65 }}>
            {typeof item === "string" ? item : JSON.stringify(item)}
          </Typography>
        </Box>
      ))}
    </Stack>
  );
}

export default function AISecurity() {
  const navigate = useNavigate();
  const location = useLocation();

  const requestedIncidentId = location.state?.incidentId || "";

  const [incidents, setIncidents] = useState([]);
  const [incidentId, setIncidentId] = useState(requestedIncidentId);
  const [incident, setIncident] = useState(null);
  const [preview, setPreview] = useState(null);
  const [socCase, setSocCase] = useState(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  const loadIncidentList = useCallback(async () => {
    const response = await api.get("/detected-incidents", {
      params: { limit: 100 },
    });

    const rows = Array.isArray(response.data?.incidents)
      ? response.data.incidents
      : [];

    setIncidents(rows);

    if (!incidentId && rows.length) {
      const preferred = requestedIncidentId
        ? rows.find((row) => String(row.incident_id) === String(requestedIncidentId))
        : null;

      setIncidentId(String((preferred || rows[0]).incident_id));
    }
  }, [incidentId, requestedIncidentId]);

  const loadInvestigation = useCallback(async (id) => {
    if (!id) return;

    setLoading(true);
    setError("");

    try {
      const [incidentResult, previewResult, caseResult] = await Promise.allSettled([
        api.get(`/detected-incidents/${encodeURIComponent(id)}`),
        api.get(`/detected-incidents/${encodeURIComponent(id)}/analysis-preview`),
        api.get(`/cases/${encodeURIComponent(id)}`),
      ]);

      if (incidentResult.status === "fulfilled") {
        setIncident(incidentResult.value.data || null);
      } else {
        setIncident(null);
      }

      if (previewResult.status === "fulfilled") {
        setPreview(previewResult.value.data || null);
      } else {
        throw new Error(
          previewResult.reason?.response?.data?.detail ||
          previewResult.reason?.message ||
          "Unable to load AI investigation preview."
        );
      }

      setSocCase(
        caseResult.status === "fulfilled"
          ? caseResult.value.data || null
          : null
      );
    } catch (err) {
      setError(err?.message || "Unable to load AI investigation.");
      setPreview(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;

    async function start() {
      try {
        await loadIncidentList();
      } catch (err) {
        if (active) {
          setError(err?.message || "Unable to load detected incidents.");
          setLoading(false);
        }
      }
    }

    start();

    return () => {
      active = false;
    };
  }, [loadIncidentList]);

  useEffect(() => {
    if (incidentId) {
      loadInvestigation(incidentId);
    }
  }, [incidentId, loadInvestigation]);

  async function runInvestigation() {
    if (!incidentId) return;

    setRunning(true);
    setError("");

    try {
      await api.post(
        `/detected-incidents/${encodeURIComponent(incidentId)}/investigate`
      );
      await loadInvestigation(incidentId);
    } catch (err) {
      setError(
        err?.response?.data?.detail ||
        err?.message ||
        "Investigation could not be promoted to the SOC workflow."
      );
    } finally {
      setRunning(false);
    }
  }

  const intelligence = object(preview?.intelligence);

  // The multi-agent pipeline stores agent products under
  // intelligence.coordinated_analysis. Keep the top-level
  // object for consensus/response/policy and read analytical
  // evidence from the coordinator payload.
  const coordinated = object(intelligence.coordinated_analysis);
  const agentOutputs = object(coordinated.agent_outputs);

  const risk = Object.keys(object(coordinated.risk)).length
    ? object(coordinated.risk)
    : object(agentOutputs.RiskAssessmentAgent);

  const investigation = Object.keys(object(coordinated.investigation)).length
    ? object(coordinated.investigation)
    : object(agentOutputs.InvestigationAgent);

  const evidence = Object.keys(object(coordinated.evidence)).length
    ? object(coordinated.evidence)
    : object(agentOutputs.EvidenceEnrichmentAgent);

  const graph = Object.keys(object(coordinated.attack_graph)).length
    ? object(coordinated.attack_graph)
    : object(agentOutputs.AttackGraphAgent);

  const graphSummary = object(graph.summary);

  const report = Object.keys(object(coordinated.report)).length
    ? object(coordinated.report)
    : object(agentOutputs.InvestigationReportAgent);
  const consensus = object(intelligence.consensus);
  const response = object(intelligence.response);
  const evidenceSummary = object(risk.evidence_summary);

  const agentDecisions = list(intelligence.agent_decisions);
  const recommendations = list(response.recommendations);
  const findings = list(investigation.findings).length
    ? list(investigation.findings)
    : list(report.key_findings);
  const graphNodes = list(object(graph.graph).nodes);

  const riskScore =
    intelligence.risk_score ?? risk.risk_score ?? preview?.multi_agent?.risk_score;
  const riskLevel =
    intelligence.risk_level ?? risk.risk_level ?? preview?.multi_agent?.risk_level;
  const finalDecision =
    intelligence.final_decision ?? consensus.final_decision ?? preview?.multi_agent?.final_decision;
  const securityState =
    intelligence.security_state ?? preview?.multi_agent?.security_state ?? response.response_level;

  const detector = useMemo(() => {
    const detections = list(incident?.detections);
    return detections[0] || {};
  }, [incident]);

  if (loading && !preview) {
    return (
      <Box sx={{ py: 8, textAlign: "center" }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading AI investigation...</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Stack
        direction={{ xs: "column", lg: "row" }}
        justifyContent="space-between"
        alignItems={{ xs: "stretch", lg: "center" }}
        spacing={2}
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800 }}>
            AI Investigation
          </Typography>
          <Typography sx={{ color: "#94a3b8", mt: 0.6 }}>
            Multi-agent analysis generated from persisted Sentinel-X evidence.
          </Typography>
        </Box>

        <Stack direction={{ xs: "column", sm: "row" }} spacing={1.2}>
          <FormControl size="small" sx={{ minWidth: 310 }}>
            <InputLabel>Detected incident</InputLabel>
            <Select
              label="Detected incident"
              value={incidentId}
              onChange={(event) => setIncidentId(event.target.value)}
            >
              {incidents.map((row) => (
                <MenuItem key={row.incident_id} value={String(row.incident_id)}>
                  {String(row.incident_id)} · Correlation {show(row.analysis_severity || row.severity)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <Button
            variant="outlined"
            startIcon={<RefreshRounded />}
            disabled={!incidentId || loading}
            onClick={() => loadInvestigation(incidentId)}
          >
            Refresh
          </Button>
        </Stack>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {!incidentId && (
        <Alert severity="info">
          No detected incident is available in the active validation database.
        </Alert>
      )}

      {preview && (
        <>
          <Card
            sx={{
              mb: 3,
              background: "linear-gradient(135deg,#161326,#111827)",
              borderColor: "rgba(139,92,246,0.35)",
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Stack
                direction={{ xs: "column", md: "row" }}
                justifyContent="space-between"
                spacing={2}
              >
                <Stack direction="row" spacing={2} alignItems="center">
                  <Box
                    sx={{
                      width: 56,
                      height: 56,
                      borderRadius: 2,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      background: "rgba(139,92,246,0.15)",
                      color: "#a78bfa",
                    }}
                  >
                    <PsychologyRounded sx={{ fontSize: 34 }} />
                  </Box>

                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 750 }}>
                      {show(detector.threat_type, "Security incident").replace(/_/g, " ")}
                    </Typography>
                    <Typography sx={{ color: "#94a3b8", fontSize: 12, mt: 0.5 }}>
                      Incident {incidentId}
                    </Typography>
                  </Box>
                </Stack>

                <Stack direction="row" spacing={1} flexWrap="wrap">
                  <Chip
                    label={show(intelligence.status || preview.multi_agent?.status, "UNKNOWN")}
                    color="success"
                    variant="outlined"
                  />
                  <Chip label="Validation only" variant="outlined" />
                  <Chip label="Real execution disabled" variant="outlined" />
                </Stack>
              </Stack>

              <Alert severity="info" sx={{ mt: 2 }}>
                This page presents investigation and response-review evidence only.
                It does not authorize or execute containment.
              </Alert>
            </CardContent>
          </Card>

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: {
                xs: "1fr",
                sm: "repeat(2,minmax(0,1fr))",
                lg: "repeat(4,minmax(0,1fr))",
              },
              gap: 2,
              mb: 3,
            }}
          >
            <MetricCard
              label="Investigation risk"
              value={riskScore === undefined ? "—" : `${riskScore} / 100`}
              color={riskColor(riskLevel)}
              subtext={show(riskLevel)}
            />
            <MetricCard
              label="Final decision"
              value={finalDecision}
              color="#a78bfa"
              subtext="Advisory multi-agent consensus"
            />
            <MetricCard
              label="Security state"
              value={securityState}
              color="#60a5fa"
              subtext="Current analysis workflow state"
            />
            <MetricCard
              label="Canonical entities"
              value={graphSummary.nodes ?? graphNodes.length}
              color="#22c55e"
              subtext={`${evidenceSummary.telemetry_categories ?? 0} telemetry category/categories`}
            />
          </Box>

          {Number.isFinite(Number(riskScore)) && (
            <Card sx={{ mb: 3 }}>
              <CardContent sx={{ p: 3 }}>
                <Stack direction="row" justifyContent="space-between" spacing={2}>
                  <Box>
                    <Typography variant="h6">Risk Assessment</Typography>
                    <Typography sx={{ color: "#94a3b8", mt: 0.5 }}>
                      {show(risk.recommended_action)}
                    </Typography>
                  </Box>
                  <Chip label={show(riskLevel)} sx={{ color: riskColor(riskLevel) }} variant="outlined" />
                </Stack>

                <LinearProgress
                  variant="determinate"
                  value={Math.max(0, Math.min(100, Number(riskScore)))}
                  sx={{ height: 9, borderRadius: 3, mt: 2, background: "#1e293b" }}
                />

                <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mt: 2 }}>
                  <Chip label={`Stored detector risk ${show(evidenceSummary.max_detection_risk)}`} size="small" />
                  <Chip label={`Detector signals ${show(evidenceSummary.max_detection_signal_count)}`} size="small" />
                  <Chip label={`Qualifying evidence ${show(evidenceSummary.qualifying_event_count)}`} size="small" />
                  <Chip label={`Cross-category ${evidenceSummary.cross_category_corroboration ? "yes" : "no"}`} size="small" />
                </Stack>
              </CardContent>
            </Card>
          )}

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", xl: "1fr 1fr" },
              gap: 2,
              mb: 3,
            }}
          >
            <Card>
              <CardContent sx={{ p: 3 }}>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                  <SearchRounded sx={{ color: "#a78bfa" }} />
                  <Typography variant="h6">Investigation Findings</Typography>
                </Stack>
                <FindingList findings={findings} />
              </CardContent>
            </Card>

            <Card>
              <CardContent sx={{ p: 3 }}>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
                  <TimelineRounded sx={{ color: "#60a5fa" }} />
                  <Typography variant="h6">Canonical Evidence</Typography>
                </Stack>

                <Stack spacing={1.2}>
                  <Typography>Process entities: <strong>{graphSummary.node_types?.PROCESS ?? graphNodes.length}</strong></Typography>
                  <Typography>Recorded process observations: <strong>{show(investigation.event_count ?? incident?.event_count ?? incident?.event_ids?.length)}</strong></Typography>
                  <Typography>Stored detection: <strong>{show(detector.engine)}</strong></Typography>
                  <Typography>Threat type: <strong>{show(detector.threat_type).replace(/_/g, " ")}</strong></Typography>
                  <Typography>Rule score: <strong>{show(detector.rule_score)}</strong></Typography>
                  <Typography>Temporal score: <strong>{show(detector.temporal_score)}</strong></Typography>
                  <Typography>Fusion score: <strong>{show(detector.fusion_score)}</strong></Typography>
                  <Typography>Production eligible: <strong>{intelligence.production_eligible ? "yes" : "no"}</strong></Typography>
                </Stack>
              </CardContent>
            </Card>
          </Box>

          <Typography variant="h6" sx={{ mb: 1.5 }}>
            Agent Decisions
          </Typography>
          <Stack spacing={1.5} sx={{ mb: 3 }}>
            {agentDecisions.length ? (
              agentDecisions.map((item, index) => (
                <DecisionCard key={`${item.agent}-${index}`} decision={item} />
              ))
            ) : (
              <Alert severity="info">No agent decision records were returned.</Alert>
            )}
          </Stack>

          <Card sx={{ mb: 3 }}>
            <CardContent sx={{ p: 3 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <ShieldRounded sx={{ color: "#22c55e" }} />
                <Typography variant="h6">Response Review</Typography>
              </Stack>

              <Typography sx={{ mt: 1.5 }}>
                Response level: <strong>{show(response.response_level)}</strong>
              </Typography>
              <Typography sx={{ color: "#94a3b8", mt: 0.5 }}>
                Consensus: {show(response.consensus_decision)} · Risk {show(response.risk_score)} {show(response.risk_level)}
              </Typography>

              <Divider sx={{ my: 2 }} />

              <Stack spacing={1.2}>
                {recommendations.map((item, index) => (
                  <Box
                    key={`${item.action}-${index}`}
                    sx={{ p: 1.6, borderRadius: 2, background: "#0f172a" }}
                  >
                    <Stack direction="row" justifyContent="space-between" spacing={1}>
                      <Typography sx={{ fontWeight: 700 }}>
                        {show(item.action).replace(/_/g, " ")}
                      </Typography>
                      <Chip
                        label={show(item.priority)}
                        size="small"
                        variant="outlined"
                      />
                    </Stack>
                    <Typography sx={{ color: "#94a3b8", mt: 0.8 }}>
                      {show(item.reason)}
                    </Typography>
                  </Box>
                ))}
              </Stack>
            </CardContent>
          </Card>

          <Card
            sx={{
              background: "linear-gradient(135deg,#11241b,#111827)",
              borderColor: "rgba(34,197,94,0.3)",
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Stack
                direction={{ xs: "column", md: "row" }}
                justifyContent="space-between"
                alignItems={{ xs: "stretch", md: "center" }}
                spacing={2}
              >
                <Box>
                  <Stack direction="row" spacing={1} alignItems="center">
                    {socCase ? (
                      <CheckCircleRounded sx={{ color: "#22c55e" }} />
                    ) : (
                      <WarningAmberRounded sx={{ color: "#f59e0b" }} />
                    )}
                    <Typography variant="h6">
                      {socCase ? "SOC Workflow Created" : "SOC Promotion Available"}
                    </Typography>
                  </Stack>

                  <Typography sx={{ color: "#94a3b8", mt: 1 }}>
                    {socCase
                      ? `Case status: ${show(socCase.status)} · Ticket: ${show(socCase.ticket?.ticket_id)}`
                      : "The analytical preview is read-only. Promotion requires an explicit investigation action."}
                  </Typography>
                </Box>

                <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                  {!socCase && (
                    <Button
                      variant="contained"
                      disabled={running}
                      startIcon={running ? <CircularProgress size={16} /> : <PsychologyRounded />}
                      onClick={runInvestigation}
                    >
                      Run Investigation
                    </Button>
                  )}

                  <Button
                    variant="outlined"
                    startIcon={<ScienceRounded />}
                    onClick={() => navigate("/response-simulator", { state: { incidentId } })}
                  >
                    Response Simulator
                  </Button>

                  <Button
                    variant="outlined"
                    endIcon={<ArrowForwardRounded />}
                    onClick={() => navigate("/approvals")}
                  >
                    Approvals
                  </Button>
                </Stack>
              </Stack>
            </CardContent>
          </Card>
        </>
      )}
    </Box>
  );
}
