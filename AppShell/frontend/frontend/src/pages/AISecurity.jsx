
import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Accordion, AccordionDetails, AccordionSummary, Alert,
  Box, Button, Card, CardContent, Checkbox, Chip,
  CircularProgress, Divider, FormControlLabel, Stack,
  TextField, Typography,
} from "@mui/material";
import {
  ArrowForwardRounded, ExpandMoreRounded, PsychologyRounded,
  RefreshRounded, SearchRounded, ShieldRounded,
} from "@mui/icons-material";
import api from "../api/sentinelApi";

const INCIDENT_LIMIT = 1000;

// Promotion remains disabled for the validation phase.
// Future enablement requires an explicit server-side eligibility result.
const SOC_PROMOTION_VALIDATED = false;

function object(value) {
  return value && typeof value === "object" &&
    !Array.isArray(value) ? value : {};
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function show(value, fallback = "Not reported") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function errorMessage(error) {
  const detail = error?.response?.data?.detail;
  return typeof detail === "string"
    ? detail
    : error?.message || "Request failed.";
}

function Field({ label, value }) {
  return (
    <Box sx={{ py: 0.8, minWidth: 0 }}>
      <Typography sx={{ color: "#94a3b8", fontSize: 12 }}>
        {label}
      </Typography>
      <Typography
        sx={{
          mt: 0.35, fontSize: 14,
          overflowWrap: "anywhere",
        }}
      >
        {show(value)}
      </Typography>
    </Box>
  );
}

function Panel({ title, data }) {
  if (data === null || data === undefined) return null;

  return (
    <Accordion sx={{ mb: 1 }}>
      <AccordionSummary expandIcon={<ExpandMoreRounded />}>
        <Typography fontWeight={650}>{title}</Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Box
          component="pre"
          sx={{
            m: 0, p: 2, borderRadius: 2,
            bgcolor: "#0f172a", color: "#cbd5e1",
            fontSize: 12, whiteSpace: "pre-wrap",
            overflowWrap: "anywhere",
            maxHeight: 350, overflow: "auto",
          }}
        >
          {JSON.stringify(data, null, 2)}
        </Box>
      </AccordionDetails>
    </Accordion>
  );
}

function Metric({ title, value, color = "#60a5fa" }) {
  return (
    <Card sx={{ height: "100%" }}>
      <CardContent sx={{ p: 2.5 }}>
        <Typography sx={{ color: "#94a3b8", fontSize: 12 }}>
          {title}
        </Typography>
        <Typography
          sx={{
            color, fontWeight: 800, fontSize: 27,
            mt: 0.8, overflowWrap: "anywhere",
          }}
        >
          {show(value)}
        </Typography>
      </CardContent>
    </Card>
  );
}

export default function AISecurity() {
  const navigate = useNavigate();
  const location = useLocation();

  const incomingId = String(
    new URLSearchParams(location.search).get("incidentId") ||
    location.state?.incidentId ||
    location.state?.incident_id ||
    ""
  ).trim();

  const [incidents, setIncidents] = useState([]);
  const [selectedId, setSelectedId] = useState(incomingId);
  const [search, setSearch] = useState("");
  const [incident, setIncident] = useState(null);
  const [preview, setPreview] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingIncident, setLoadingIncident] = useState(false);
  const [running, setRunning] = useState(false);
  const [listError, setListError] = useState("");
  const [incidentError, setIncidentError] = useState("");
  const [runError, setRunError] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);

  const loadIncidents = useCallback(async () => {
    setLoadingList(true);
    setListError("");
    try {
      const response = await api.get("/detected-incidents", {
        params: { limit: INCIDENT_LIMIT },
      });
      setIncidents(list(response.data?.incidents));
      if (Number(response.data?.count) >= INCIDENT_LIMIT) {
        setListError(
          "Only the first 1,000 incidents were requested."
        );
      }
    } catch (error) {
      setIncidents([]);
      setListError(errorMessage(error));
    } finally {
      setLoadingList(false);
    }
  }, []);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  useEffect(() => {
    if (incomingId) setSelectedId(incomingId);
  }, [incomingId]);

  useEffect(() => {
    let active = true;
    setIncident(null);
    setPreview(null);
    setIncidentError("");
    setRunError("");
    setAcknowledged(false);

    if (!selectedId) {
      setLoadingIncident(false);
      return () => { active = false; };
    }

    setLoadingIncident(true);

    api.get(
      `/detected-incidents/${encodeURIComponent(selectedId)}`
    ).then((response) => {
      if (active) setIncident(response.data);
    }).catch((error) => {
      if (active) setIncidentError(errorMessage(error));
    }).finally(() => {
      if (active) setLoadingIncident(false);
    });

    return () => { active = false; };
  }, [selectedId]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return incidents.filter((item) => {
      if (!q) return true;
      return [
        item.incident_id, item.title,
        item.severity, item.status,
        ...list(item.categories),
      ].some((v) => String(v ?? "").toLowerCase().includes(q));
    });
  }, [incidents, search]);

  const selectedFromList = incidents.find(
    (item) => String(item.incident_id) === selectedId
  );

  const current = incident || selectedFromList || null;
  const timeline = list(incident?.timeline);
  const intelligence = object(preview?.intelligence);
  const validation = object(intelligence.evidence_validation);
  const coordinated = object(intelligence.coordinated_analysis);
  const outputs = object(coordinated.agent_outputs);
  const decisions = list(intelligence.agent_decisions);

  const passed = validation.passed === true;
  const complete =
    String(intelligence.status || preview?.status || "")
      .toUpperCase() === "COMPLETED";

  const alreadyInSoc =
    current?.soc_case_exists === true ||
    preview?.already_in_soc === true;

  // No promotion without backend authorization, even if the
  // UI displays a completed investigation.
  const eligible = Boolean(
    SOC_PROMOTION_VALIDATED &&
    complete &&
    passed &&
    preview?.promotion_eligible === true &&
    !alreadyInSoc
  );

  const canPreview = Boolean(
    incident?.incident_id &&
    acknowledged &&
    !loadingIncident &&
    !running
  );

  async function runPreview() {
    if (!canPreview) return;

    const id = incident.incident_id;
    setRunning(true);
    setRunError("");
    setPreview(null);

    try {
      const response = await api.get(
        `/detected-incidents/${encodeURIComponent(id)}/analysis-preview`
      );

      if (String(response.data?.incident_id || id) !== String(id)) {
        throw new Error("Investigation incident identity mismatch.");
      }

      setPreview(response.data);
    } catch (error) {
      setRunError(errorMessage(error));
    } finally {
      setRunning(false);
    }
  }

  const categoryCounts = useMemo(() => {
    const counts = {};
    for (const item of timeline) {
      const category = String(
        item.event_category || "UNKNOWN"
      ).toUpperCase();
      counts[category] = (counts[category] || 0) + 1;
    }
    return counts;
  }, [timeline]);

  return (
    <Box sx={{ pb: 4 }}>
      <Stack
        direction={{ xs: "column", sm: "row" }}
        justifyContent="space-between"
        alignItems={{ xs: "stretch", sm: "center" }}
        spacing={2}
        sx={{ mb: 3 }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 750 }}>
            AI Investigation
          </Typography>
          <Typography sx={{ color: "#94a3b8", mt: 0.5 }}>
            Read-only investigation of persisted SENTINEL-X incidents.
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={<RefreshRounded />}
          onClick={loadIncidents}
          disabled={loadingList || running}
        >
          Refresh Incidents
        </Button>
      </Stack>

      <Alert severity="info" sx={{ mb: 3 }}>
        Detection severity is not proof of an attack.
        SHADOW observations, INFO events, identity mismatches
        and model uncertainty are subject to evidence validation.
      </Alert>

      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
            <SearchRounded sx={{ color: "#a78bfa" }} />
            <Typography variant="h6">
              Select a Stored Incident
            </Typography>
          </Stack>

          <TextField
            fullWidth
            size="small"
            label="Search incidents"
            value={search}
            placeholder="Incident ID, title, severity..."
            onChange={(event) => setSearch(event.target.value)}
            sx={{ mb: 2 }}
          />

          {loadingList && <CircularProgress size={22} />}

          {listError && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              {listError}
            </Alert>
          )}

          <Box sx={{ maxHeight: 245, overflowY: "auto" }}>
            {filtered.map((item) => {
              const id = String(item.incident_id);
              const active = id === selectedId;

              return (
                <Box
                  key={id}
                  onClick={() => setSelectedId(id)}
                  sx={{
                    cursor: "pointer",
                    mb: 1, p: 1.5, borderRadius: 2,
                    border: active
                      ? "1px solid #60a5fa"
                      : "1px solid #263244",
                    bgcolor: active
                      ? "rgba(59,130,246,0.10)"
                      : "rgba(15,23,42,0.50)",
                  }}
                >
                  <Stack
                    direction={{ xs: "column", sm: "row" }}
                    justifyContent="space-between"
                    spacing={1}
                  >
                    <Box sx={{ minWidth: 0 }}>
                      <Typography fontWeight={650}>
                        {show(item.title, "Untitled incident")}
                      </Typography>
                      <Typography
                        sx={{
                          fontSize: 11,
                          color: "#94a3b8",
                          overflowWrap: "anywhere",
                        }}
                      >
                        {id}
                      </Typography>
                    </Box>
                    <Stack direction="row" spacing={1}>
                      <Chip size="small" label={show(item.severity)} />
                      {item.soc_case_exists && (
                        <Chip
                          size="small"
                          color="success"
                          label="SOC Case"
                        />
                      )}
                    </Stack>
                  </Stack>
                </Box>
              );
            })}
          </Box>

          {!loadingList && !filtered.length && (
            <Alert severity="info">
              No matching detected incidents.
            </Alert>
          )}
        </CardContent>
      </Card>

      {loadingIncident && (
        <CircularProgress size={22} sx={{ mb: 2 }} />
      )}
      {incidentError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {incidentError}
        </Alert>
      )}

      {current && (
        <>
          <Card sx={{ mb: 3 }}>
            <CardContent sx={{ p: 3 }}>
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                sx={{ mb: 2 }}
              >
                <PsychologyRounded sx={{ color: "#a78bfa" }} />
                <Typography variant="h6">
                  Incident Evidence
                </Typography>
              </Stack>

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    md: "repeat(3,1fr)",
                  },
                  gap: 2,
                }}
              >
                <Field label="Incident ID" value={current.incident_id} />
                <Field label="Severity" value={current.severity} />
                <Field label="Current status" value={current.status} />
                <Field label="Recorded event count" value={current.event_count} />
                <Field label="Source" value={current.source} />
                <Field
                  label="SOC case"
                  value={
                    alreadyInSoc
                      ? "Existing persisted case"
                      : "Not promoted"
                  }
                />
              </Box>

              <Divider sx={{ my: 2 }} />

              <Typography fontWeight={700}>
                Timeline categories
              </Typography>
              <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 1 }}>
                {Object.entries(categoryCounts).map(([key, count]) => (
                  <Chip key={key} label={`${key}: ${count}`} />
                ))}
                {!timeline.length && (
                  <Typography color="text.secondary">
                    No timeline entries supplied.
                  </Typography>
                )}
              </Stack>

              <Panel
                title={`Recorded incident timeline (${timeline.length})`}
                data={timeline}
              />

              <FormControlLabel
                sx={{ mt: 2 }}
                control={
                  <Checkbox
                    checked={acknowledged}
                    onChange={(event) =>
                      setAcknowledged(event.target.checked)
                    }
                  />
                }
                label="I understand that observed anomalies are not necessarily verified threats."
              />

              <Stack
                direction={{ xs: "column", sm: "row" }}
                spacing={2}
                sx={{ mt: 2 }}
              >
                <Button
                  variant="contained"
                  startIcon={<PsychologyRounded />}
                  disabled={!canPreview}
                  onClick={runPreview}
                >
                  {running ? "Analyzing..." : "Run AI Investigation Preview"}
                </Button>

                <Button
                  variant="outlined"
                  startIcon={<ArrowForwardRounded />}
                  onClick={() => navigate(
                    `/response-simulator?incidentId=${encodeURIComponent(selectedId)}`
                  )}
                >
                  Open Response Simulator
                </Button>
              </Stack>
            </CardContent>
          </Card>

          {running && (
            <Alert severity="info" sx={{ mb: 2 }}>
              Running read-only multi-agent analysis...
            </Alert>
          )}
          {runError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {runError}
            </Alert>
          )}
        </>
      )}

      {preview && (
        <>
          <Card sx={{ mb: 3 }}>
            <CardContent sx={{ p: 3 }}>
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                sx={{ mb: 2 }}
              >
                <ShieldRounded sx={{ color: "#60a5fa" }} />
                <Typography variant="h6">
                  Evidence Validation
                </Typography>
                <Chip
                  size="small"
                  color={passed ? "success" : "warning"}
                  label={passed ? "PASSED" : "INSUFFICIENT"}
                />
              </Stack>

              <Box
                sx={{
                  display: "grid",
                  gridTemplateColumns: {
                    xs: "1fr",
                    md: "repeat(4,1fr)",
                  },
                  gap: 2,
                }}
              >
                <Metric
                  title="Investigation status"
                  value={intelligence.status || preview.status}
                  color={complete ? "#22c55e" : "#f59e0b"}
                />
                <Metric
                  title="Authoritative events"
                  value={validation.authoritative_event_count ?? "—"}
                />
                <Metric
                  title="Rejected events"
                  value={validation.rejected_event_count ?? "—"}
                  color="#f59e0b"
                />
                <Metric
                  title="Investigation risk"
                  value={
                    complete && passed
                      ? intelligence.risk_score ?? "—"
                      : "Unvalidated"
                  }
                />
              </Box>

              <Alert
                severity={passed && complete ? "success" : "warning"}
                sx={{ mt: 2 }}
              >
                {passed && complete
                  ? "Evidence validation passed. SOC promotion remains locked until a server-authorized workflow is validated."
                  : "Investigation is incomplete or evidence validation failed. No authoritative response is recommended."}
              </Alert>

              {list(validation.reasons).map((reason, index) => (
                <Typography
                  key={index}
                  sx={{ color: "#fbbf24", fontSize: 13, mt: 1 }}
                >
                  • {reason}
                </Typography>
              ))}

              <Stack
                direction="row"
                spacing={1}
                sx={{ mt: 2 }}
                flexWrap="wrap"
              >
                {list(validation.rejected_reasons).map((reason, index) => (
                  <Chip key={index} size="small" label={reason} />
                ))}
              </Stack>

              <Panel
                title="Authoritative categories by device"
                data={validation.categories_by_device}
              />
              <Panel
                title="Evidence validation details"
                data={validation}
              />
            </CardContent>
          </Card>

          <Card sx={{ mb: 3 }}>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Multi-Agent Investigation
              </Typography>

              <Field label="Investigation status" value={intelligence.status} />
              <Field
                label="Final decision"
                value={intelligence.final_decision}
              />
              <Field
                label="Security state"
                value={intelligence.security_state}
              />
              <Field
                label="Agent count"
                value={Object.keys(outputs).length}
              />

              {Object.entries(outputs).map(([name, output]) => (
                <Panel key={name} title={`Agent: ${name}`} data={output} />
              ))}

              <Panel
                title={`Agent decisions (${decisions.length})`}
                data={decisions}
              />
              <Panel
                title="Coordinated analysis"
                data={coordinated}
              />
              <Panel
                title="Full investigation response"
                data={preview}
              />
            </CardContent>
          </Card>
        </>
      )}

      <Card
        sx={{
          borderColor: "rgba(59,130,246,0.35)",
          background:
            "linear-gradient(135deg,#111c30,#111827)",
        }}
      >
        <CardContent sx={{ p: 3 }}>
          <Typography variant="h6">
            SOC Promotion
          </Typography>

          <Typography sx={{ color: "#94a3b8", mt: 1, mb: 2 }}>
            Promotion is locked during validation. Completing a
            read-only investigation never creates a SOC case.
            Future promotion must require explicit server-side
            eligibility checks and operator confirmation.
          </Typography>

          <Button
            variant="contained"
            disabled={!eligible}
            startIcon={<ShieldRounded />}
          >
            Promote to SOC
          </Button>

          {alreadyInSoc && (
            <Button
              sx={{ ml: 2 }}
              variant="outlined"
              onClick={() => navigate(`/incidents/${selectedId}`)}
            >
              View Existing Incident
            </Button>
          )}

          <Alert severity="info" sx={{ mt: 2 }}>
            SOC promotion: disabled for this validation release.
            No POST investigation or case-creation requests are
            issued by this page.
          </Alert>
        </CardContent>
      </Card>
    </Box>
  );
}
