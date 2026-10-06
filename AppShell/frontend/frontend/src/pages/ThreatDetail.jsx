import { useEffect, useState } from "react";
import {
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";

import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
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
  Typography,
} from "@mui/material";

import {
  ArrowBackRounded,
  ExpandMoreRounded,
  PsychologyRounded,
  ScienceRounded,
  ShieldRounded,
  TimelineRounded,
  WarningAmberRounded,
} from "@mui/icons-material";

import api, {
  getLiveDetections,
} from "../api/sentinelApi";

const INCIDENT_LIMIT = 1000;

function show(value, fallback = "Not reported") {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return fallback;
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function formatTime(value) {
  if (!value) return "Not reported";

  if (
    typeof value === "string" &&
    !/[zZ]$|[+-]\d\d:\d\d$/.test(value)
  ) {
    return `${value} (timezone unspecified)`;
  }

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
}

function key(value) {
  return String(value ?? "").trim().toLowerCase();
}

function humanizeThreatType(value) {
  if (!value) return "";

  const text = String(value)
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

  return text
    .replace(/Powershell/g, "PowerShell")
    .replace(/Cmd/g, "CMD")
    .replace(/Mshta/g, "MSHTA")
    .replace(/Wscript/g, "WScript")
    .replace(/Cscript/g, "CScript")
    .replace(/Regsvr32/g, "Regsvr32")
    .replace(/Rundll32/g, "Rundll32");
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
      // The stored reason may be plain text.
    }

    return value ? [value.replace(/_/g, " ")] : [];
  }

  return [];
}

function numeric(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function severityColor(severity) {
  switch (String(severity || "").toUpperCase()) {
    case "CRITICAL": return "#ef4444";
    case "HIGH": return "#f97316";
    case "MEDIUM": return "#f59e0b";
    case "LOW": return "#3b82f6";
    default: return "#94a3b8";
  }
}

function eventMatchesIncident(eventId, incident) {
  return (
    Boolean(eventId) &&
    Array.isArray(incident?.event_ids) &&
    incident.event_ids.some((id) => key(id) === key(eventId))
  );
}

async function getIncidents() {
  const response = await api.get("/detected-incidents", {
    params: { limit: INCIDENT_LIMIT },
  });

  const incidents = response.data?.incidents;

  return {
    incidents: Array.isArray(incidents) ? incidents : [],
    truncated:
      Array.isArray(incidents) && incidents.length >= INCIDENT_LIMIT,
  };
}

function getExplanation(detection) {
  const process = detection.process_evidence || {};
  const scores = detection.model_scores || {};
  const forest = process.isolation_forest || {};
  const encoder = process.autoencoder || {};
  const temporal = process.temporal || {};

  const statements = [];

  const ruleScore = numeric(
    scores.rule_score ?? process.behavior_score
  );

  const temporalScore = numeric(
    scores.temporal_score ?? temporal.score
  );

  const fusionScore = numeric(
    scores.fusion_score ?? process.fusion_score
  );

  if (ruleScore !== null) {
    statements.push(
      `Rule evidence score: ${ruleScore}.`
    );
  }

  if (temporalScore !== null) {
    statements.push(
      `Temporal AI score: ${temporalScore}` +
      `${temporal.label ? ` (${show(temporal.label).replace(/_/g, " ")})` : ""}.`
    );
  }

  if (fusionScore !== null) {
    statements.push(
      `Fusion-v3 combined evidence score: ${fusionScore}` +
      `${process.fusion_severity ? ` (${show(process.fusion_severity)})` : ""}.`
    );
  }

  if (forest.available === true) {
    statements.push(
      `Isolation Forest result: ${show(
        forest.anomaly_label,
        forest.model_outlier === true ? "ANOMALOUS" : "NORMAL"
      )} (${show(forest.anomaly_confidence)}).`
    );
  }

  if (
    encoder.available === true &&
    (encoder.anomaly_label ||
      numeric(encoder.reconstruction_error) !== null)
  ) {
    statements.push(
      `Autoencoder result: ${show(
        encoder.anomaly_label,
        "Anomaly measure recorded"
      )} (${show(encoder.anomaly_confidence)}).`
    );
  }

  if (scores.ai_agreement) {
    statements.push(
      `Reported model agreement: ${show(scores.ai_agreement)}.`
    );
  }

  if (!statements.length) {
    statements.push(
      "A detection was recorded, but the available API evidence does not explain its underlying model contributions."
    );
  }

  return statements;
}

function DetailField({ label, value }) {
  return (
    <Box sx={{ py: 1.1 }}>
      <Typography sx={{ color: "#94a3b8", fontSize: 12 }}>
        {label}
      </Typography>
      <Typography
        sx={{
          mt: 0.35,
          fontSize: 13,
          overflowWrap: "anywhere",
        }}
      >
        {show(value)}
      </Typography>
      <Divider sx={{ mt: 1.1 }} />
    </Box>
  );
}

function ModelCard({ title, model, modelType }) {
  const available = model?.available === true;

  if (!available) {
    return (
      <Card variant="outlined">
        <CardContent>
          <Typography sx={{ fontWeight: 700 }}>{title}</Typography>
          <Typography sx={{ color: "#94a3b8", mt: 1 }}>
            No model details available in this record.
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const reportedScore = numeric(model.anomaly_confidence);

  return (
    <Card
      variant="outlined"
      sx={{ borderColor: "rgba(139,92,246,0.35)" }}
    >
      <CardContent sx={{ p: 2.5 }}>
        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="flex-start"
          spacing={1}
        >
          <Typography sx={{ fontWeight: 700 }}>
            {title}
          </Typography>

          <Chip
            size="small"
            label={show(model.anomaly_label, "Result recorded")}
            variant="outlined"
          />
        </Stack>

        <Typography sx={{ color: "#94a3b8", fontSize: 12, mt: 1.5 }}>
          Reported anomaly measure
        </Typography>

        <Typography sx={{ fontSize: 24, fontWeight: 750 }}>
          {reportedScore === null
            ? "Not reported"
            : reportedScore}
        </Typography>

        {reportedScore !== null && (
          <LinearProgress
            variant="determinate"
            value={Math.max(0, Math.min(100, reportedScore))}
            sx={{
              mt: 1,
              height: 7,
              borderRadius: 2,
              background: "#1e293b",
            }}
          />
        )}

        <Typography
          sx={{ color: "#64748b", fontSize: 11, mt: 1 }}
        >
          Model-reported anomaly measure, not a calibrated
          probability of malicious activity.
        </Typography>

        <DetailField
          label="Model version"
          value={model.model_version}
        />

        {modelType === "forest" ? (
          <>
            <DetailField
              label="Model outlier"
              value={
                model.model_outlier === undefined
                  ? null
                  : String(model.model_outlier)
              }
            />
            <DetailField
              label="Decision score"
              value={model.decision_score}
            />
          </>
        ) : (
          <>
            <DetailField
              label="Reconstruction error"
              value={model.reconstruction_error}
            />
            <DetailField
              label="Reconstruction region"
              value={model.reconstruction_region}
            />
          </>
        )}
      </CardContent>
    </Card>
  );
}

function FeatureEvidence({ forest, encoder }) {
  const deviations = Array.isArray(forest?.feature_deviations)
    ? forest.feature_deviations
    : [];

  const reconstruction = Array.isArray(
    encoder?.feature_reconstruction_errors
  )
    ? encoder.feature_reconstruction_errors
    : [];

  if (!deviations.length && !reconstruction.length) {
    return (
      <Alert severity="info">
        No individual feature explanations were saved for
        this detection.
      </Alert>
    );
  }

  return (
    <Stack spacing={2}>
      {deviations.length > 0 && (
        <Box>
          <Typography sx={{ fontWeight: 700, mb: 1 }}>
            Isolation Forest feature deviations
          </Typography>

          <Typography
            sx={{ color: "#94a3b8", fontSize: 12, mb: 1.5 }}
          >
            These values describe deviations from the model's
            reference distribution, not malicious actions.
          </Typography>

          {deviations.slice(0, 5).map((item, index) => (
            <Box
              key={`${item.feature}-${index}`}
              sx={{
                p: 1.5,
                mb: 1,
                background: "#0f172a",
                borderRadius: 2,
              }}
            >
              <Typography sx={{ fontWeight: 650 }}>
                {show(item.feature).replace(/_/g, " ")}
              </Typography>

              <Typography
                sx={{ color: "#94a3b8", fontSize: 12, mt: 0.4 }}
              >
                Observed: {show(item.value)}
                {" · "}
                Reference mean: {show(item.baseline_mean)}
                {" · "}
                Deviation: {show(item.deviation_std)} SD
              </Typography>
            </Box>
          ))}
        </Box>
      )}

      {reconstruction.length > 0 && (
        <Box>
          <Typography sx={{ fontWeight: 700, mb: 1 }}>
            Autoencoder reconstruction differences
          </Typography>

          {reconstruction.slice(0, 5).map((item, index) => (
            <Box
              key={`${item.feature}-${index}`}
              sx={{
                p: 1.5,
                mb: 1,
                background: "#0f172a",
                borderRadius: 2,
              }}
            >
              <Typography sx={{ fontWeight: 650 }}>
                {show(item.feature).replace(/_/g, " ")}
              </Typography>

              <Typography
                sx={{ color: "#94a3b8", fontSize: 12, mt: 0.4 }}
              >
                Actual: {show(item.actual_value)}
                {" · "}
                Reconstructed: {show(item.reconstructed_value)}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
    </Stack>
  );
}

function TimelineEntry({ item, index }) {
  const event =
    item && typeof item === "object"
      ? item
      : { description: String(item) };

  const title = (
    event.title ||
    event.event_type ||
    event.category ||
    event.type ||
    "Recorded event"
  ).toString().replace(/_/g, " ");

  const description =
    event.description ||
    event.message ||
    event.reason ||
    event.event_id ||
    "No further event description was recorded.";

  return (
    <Box
      sx={{
        display: "flex",
        gap: 2,
        pb: 2,
        mb: 1,
        borderBottom: "1px solid #1e293b",
      }}
    >
      <TimelineRounded sx={{ color: "#60a5fa", mt: 0.3 }} />

      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography sx={{ fontWeight: 650 }}>
          {title}
        </Typography>

        <Typography
          sx={{
            fontSize: 12,
            color: "#94a3b8",
            mt: 0.5,
            overflowWrap: "anywhere",
          }}
        >
          {show(description)}
        </Typography>

        <Typography
          sx={{ fontSize: 11, color: "#64748b", mt: 0.5 }}
        >
          {formatTime(event.timestamp || event.time)}
        </Typography>
      </Box>
    </Box>
  );
}

export default function ThreatDetail() {
  const navigate = useNavigate();
  const location = useLocation();
  const { threatId } = useParams();

  const requestedId = String(threatId || "").replace(
    /^detection-/,
    ""
  );

  const stateDetection = location.state?.detection;
  const matchingStateDetection =
    String(stateDetection?.detection_id ?? "") === requestedId
      ? stateDetection
      : null;

  const stateIncident = location.state?.incident;

  const [detection, setDetection] = useState(
    matchingStateDetection
  );
  const [incidents, setIncidents] = useState(
    stateIncident ? [stateIncident] : []
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [incidentError, setIncidentError] = useState("");
  const [incidentTruncated, setIncidentTruncated] = useState(false);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);

      const [detResult, incResult] = await Promise.allSettled([
        getLiveDetections(100),
        getIncidents(),
      ]);

      if (!active) return;

      let resolved = matchingStateDetection;

      if (detResult.status === "fulfilled") {
        const records = Array.isArray(
          detResult.value?.detections
        )
          ? detResult.value.detections
          : [];

        const latest = records.find(
          (item) => String(item.detection_id) === requestedId
        );

        if (latest) resolved = latest;
        setError("");
      } else {
        setError(
          detResult.reason?.message ||
          "Unable to refresh the detection."
        );
      }

      setDetection(resolved || null);

      if (incResult.status === "fulfilled") {
        const allIncidents = incResult.value.incidents;

        const matches = allIncidents.filter(
          (item) =>
            eventMatchesIncident(resolved?.event_id, item) ||
            (
              resolved?.incident_id &&
              String(item.incident_id) ===
              String(resolved.incident_id)
            )
        );

        const verifiedStateIncident =
          stateIncident &&
          (
            eventMatchesIncident(resolved?.event_id, stateIncident) ||
            (
              resolved?.incident_id &&
              String(stateIncident.incident_id) ===
              String(resolved.incident_id)
            )
          )
            ? stateIncident
            : null;

        setIncidents(
          matches.length
            ? matches
            : verifiedStateIncident
              ? [verifiedStateIncident]
              : []
        );

        setIncidentTruncated(incResult.value.truncated);
        setIncidentError("");
      } else {
        setIncidentError(
          incResult.reason?.message ||
          "Unable to refresh incident information."
        );
      }

      setLoading(false);
    }

    load();

    return () => {
      active = false;
    };
  }, [
    requestedId,
    matchingStateDetection,
    stateIncident,
  ]);

  if (loading && !detection) {
    return (
      <Box sx={{ textAlign: "center", py: 5 }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>
          Loading detection evidence...
        </Typography>
      </Box>
    );
  }

  if (!detection) {
    return (
      <Box>
        <Button
          startIcon={<ArrowBackRounded />}
          onClick={() => navigate("/threats")}
          sx={{ mb: 2 }}
        >
          Back to Threats
        </Button>

        <Alert severity="warning">
          Detection #{requestedId} was not found in the
          latest 100 API results. Older direct links will need
          an ID-based read endpoint.
        </Alert>
      </Box>
    );
  }

  const process = detection.process_evidence || {};
  const scores = detection.model_scores || {};
  const forest = process.isolation_forest || {};
  const encoder = process.autoencoder || {};

  const incident = incidents[0] || null;
  const incidentId =
    incident?.incident_id ||
    detection.incident_id ||
    null;

  const processName =
    detection.process_name ||
    process.process_name ||
    null;

  const threatLabel =
    humanizeThreatType(detection.threat_type) ||
    detection.display_title ||
    "Security Detection";

  const title =
    processName &&
    !String(threatLabel)
      .toLowerCase()
      .includes(String(processName).toLowerCase())
      ? `${threatLabel} - ${processName}`
      : threatLabel;

  const severity = String(
    detection.severity || "UNKNOWN"
  ).toUpperCase();

  const color = severityColor(severity);
  const risk = numeric(detection.risk_score);

  const reasons = reasonsOf(
    detection.detection_reason ?? process.fusion_reasons
  );

  const ruleScore = numeric(
    scores.rule_score ?? process.behavior_score
  );
  const statisticalScore = numeric(
    scores.statistical_score ?? process.statistical_score
  );
  const temporalScore = numeric(
    scores.temporal_score ?? process.temporal?.score
  );
  const behavioralAiScore = numeric(
    scores.ai_consensus_score ??
      process.ai_consensus_score ??
      process.behavior_ai_score
  );

  const corroboratingSignals = [
    ...(ruleScore !== null && ruleScore >= 35 ? ["Rules"] : []),
    ...(statisticalScore !== null && statisticalScore >= 35
      ? ["Statistical"]
      : []),
    ...(behavioralAiScore !== null && behavioralAiScore >= 60
      ? ["Behavioral AI"]
      : []),
    ...(temporalScore !== null && temporalScore >= 60
      ? ["Temporal AI"]
      : []),
  ];

  const timeline = Array.isArray(incident?.timeline)
    ? incident.timeline
    : [];

  const explanations = getExplanation(detection);

  const processAgeFlag =
    processName?.toLowerCase() === "system" &&
    (
      numeric(process.create_time) === 0 ||
      (numeric(process.pid) === 4)
    );

  return (
    <Box>
      <Button
        startIcon={<ArrowBackRounded />}
        onClick={() => navigate("/threats")}
        sx={{ mb: 2 }}
      >
        Back to Threats
      </Button>

      {error && (
        <Alert severity="warning" sx={{ mb: 2 }}>
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
          Only the most recent 1,000 incident records were
          checked. Older relationships may not appear here.
        </Alert>
      )}

      {/* HEADER */}

      <Stack
        direction={{ xs: "column", md: "row" }}
        justifyContent="space-between"
        alignItems={{ xs: "flex-start", md: "center" }}
        spacing={2}
        sx={{ mb: 3 }}
      >
        <Box>
          <Stack direction="row" spacing={1.5} alignItems="center">
            <WarningAmberRounded sx={{ color, fontSize: 32 }} />

            <Typography variant="h4" sx={{ fontWeight: 750 }}>
              {title}
            </Typography>
          </Stack>

          <Typography
            sx={{ color: "#94a3b8", mt: 1, fontSize: 13 }}
          >
            Detection #{show(detection.detection_id)}
            {" · "}
            PID {show(detection.pid ?? process.pid)}
            {" · "}
            {show(detection.device_id)}
          </Typography>

          <Stack direction="row" spacing={1} sx={{ mt: 1.5 }}>
            <Chip label={severity} sx={{ color }} variant="outlined" />

            <Chip
              label={
                incidentId
                  ? "Incident Linked"
                  : "Link Not Verified"
              }
              color={incidentId ? "success" : "default"}
              variant="outlined"
            />

            {incident && (
              <Chip
                label={show(incident.status, "Unknown status")}
                variant="outlined"
              />
            )}
          </Stack>
        </Box>

        <Button
          variant="contained"
          disabled={!incidentId}
          startIcon={<ShieldRounded />}
          onClick={() =>
            navigate("/response-simulator", {
              state: { incidentId },
            })
          }
        >
          Review Response Workflow
        </Button>
      </Stack>

      {/* OVERVIEW */}

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: {
            xs: "1fr",
            md: "repeat(2,1fr)",
          },
          gap: 2,
          mb: 3,
        }}
      >
        <Card>
          <CardContent sx={{ p: 3 }}>
            <Typography variant="h6">
              Detection Risk
            </Typography>

            <Typography
              sx={{ fontSize: 46, fontWeight: 800, color, mt: 1 }}
            >
              {risk === null ? "—" : risk}
              <Typography
                component="span"
                sx={{ fontSize: 15, color: "#94a3b8" }}
              >
                {risk === null ? "" : " / 100"}
              </Typography>
            </Typography>

            {risk !== null && (
              <LinearProgress
                variant="determinate"
                value={Math.max(0, Math.min(100, risk))}
                sx={{
                  height: 9,
                  borderRadius: 2,
                  background: "#1e293b",
                }}
              />
            )}

            <Typography
              sx={{ color: "#94a3b8", fontSize: 12, mt: 1.5 }}
            >
              Stored fusion risk measure. Not a probability
              that this process is malicious.
            </Typography>
          </CardContent>
        </Card>

        <Card>
          <CardContent sx={{ p: 3 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <PsychologyRounded sx={{ color: "#a78bfa" }} />
              <Typography variant="h6">
                Evidence Corroboration
              </Typography>
            </Stack>

            <Typography sx={{ fontSize: 28, fontWeight: 750, mt: 2 }}>
              {corroboratingSignals.length
                ? `${corroboratingSignals.length} independent signal${
                    corroboratingSignals.length === 1 ? "" : "s"
                  }`
                : "No corroboration reported"}
            </Typography>

            <Typography
              sx={{ color: "#94a3b8", mt: 1, fontSize: 13 }}
            >
              {corroboratingSignals.length
                ? corroboratingSignals.join(" + ")
                : "No independently active evidence categories were available."}
            </Typography>

            <Typography
              sx={{ color: "#64748b", mt: 1, fontSize: 12 }}
            >
              Corroboration is not a calibrated probability of
              malicious activity and does not authorize containment.
            </Typography>
          </CardContent>
        </Card>
      </Box>

      {/* WHAT HAPPENED */}

      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <TimelineRounded sx={{ color: "#60a5fa" }} />
            <Typography variant="h6">
              What Happened?
            </Typography>
          </Stack>

          <Typography sx={{ mt: 2, lineHeight: 1.8 }}>
            Sentinel-X recorded a detection for
            {" "}
            <strong>{show(processName, "an endpoint event")}</strong>
            {" "}
            using the
            {" "}
            <strong>{show(detection.engine)}</strong>
            {" "}
            detection engine.
          </Typography>

          <DetailField
            label="Original event"
            value={detection.event_id}
          />

          <DetailField
            label="Event type"
            value={detection.event_type}
          />

          <DetailField
            label="Timestamp"
            value={formatTime(detection.timestamp)}
          />

          <DetailField
            label="Parent process"
            value={
              detection.parent_process_name ??
              process.parent_process_name
            }
          />

          <DetailField
            label="Detection reason"
            value={
              reasons.length
                ? reasons.join(", ")
                : "No specific reason recorded"
            }
          />

          {incident && (
            <Alert severity="info" sx={{ mt: 2 }}>
              This event is associated with recorded incident
              {" "}
              {incident.incident_id}.
              {" "}
              Its current status is
              {" "}
              {show(incident.status)}.
            </Alert>
          )}

          <Typography sx={{ fontWeight: 700, mt: 3, mb: 1.5 }}>
            Recorded Incident Timeline
          </Typography>

          {timeline.length ? (
            timeline.map((item, index) => (
              <TimelineEntry
                key={index}
                item={item}
                index={index}
              />
            ))
          ) : (
            <Alert severity="info">
              No detailed incident timeline was available
              in the retrieved incident record.
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* AI EXPLANATION */}

      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 3 }}>
          <Stack direction="row" spacing={1} alignItems="center">
            <PsychologyRounded sx={{ color: "#a78bfa" }} />
            <Typography variant="h6">
              Why Sentinel-X Flagged This
            </Typography>
          </Stack>

          <Stack spacing={1.5} sx={{ mt: 2 }}>
            {explanations.map((text, index) => (
              <Typography key={index} sx={{ color: "#cbd5e1" }}>
                • {text}
              </Typography>
            ))}
          </Stack>

          <Alert severity="warning" sx={{ mt: 2 }}>
            {detection.threat_type
              ? `Detector classification: ${humanizeThreatType(
                  detection.threat_type
                )}. This classification is supported by recorded detection evidence, but it still requires analyst validation and does not authorize containment.`
              : "No specific detector classification was stored. Model anomaly evidence alone does not establish an attack type."}
          </Alert>

          {processAgeFlag && (
            <Alert severity="info" sx={{ mt: 2 }}>
              This is the Windows System process. Its PID or
              stored creation time requires special handling
              when interpreting process-age features.
              Check the feature calculation before treating
              a high anomaly score as malicious evidence.
            </Alert>
          )}

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: {
                xs: "1fr",
                md: "1fr 1fr",
              },
              gap: 2,
              mt: 3,
            }}
          >
            <ModelCard
              title="Isolation Forest"
              model={forest}
              modelType="forest"
            />
            <ModelCard
              title="Autoencoder"
              model={encoder}
              modelType="encoder"
            />
          </Box>

          <Typography variant="h6" sx={{ mt: 3, mb: 1.5 }}>
            Features Behind the Alert
          </Typography>

          <FeatureEvidence forest={forest} encoder={encoder} />
        </CardContent>
      </Card>

      {/* ADVANCED DETAILS */}

      <Accordion sx={{ mb: 3 }}>
        <AccordionSummary expandIcon={<ExpandMoreRounded />}>
          <Typography sx={{ fontWeight: 700 }}>
            Advanced Technical Details
          </Typography>
        </AccordionSummary>

        <AccordionDetails>
          <DetailField
            label="Detection ID"
            value={detection.detection_id}
          />
          <DetailField
            label="Event ID"
            value={detection.event_id}
          />
          <DetailField
            label="Device ID"
            value={detection.device_id}
          />
          <DetailField
            label="Process"
            value={processName}
          />
          <DetailField
            label="PID"
            value={detection.pid ?? process.pid}
          />
          <DetailField
            label="Parent PID"
            value={process.ppid}
          />
          <DetailField
            label="Parent process"
            value={process.parent_process_name}
          />
          <DetailField
            label="Thread count"
            value={process.num_threads}
          />
          <DetailField
            label="Handle count"
            value={process.num_handles}
          />
          <DetailField
            label="CPU percent"
            value={process.cpu_percent}
          />
          <DetailField
            label="Memory percent"
            value={process.memory_percent}
          />
          <DetailField
            label="Stored fusion version"
            value={process.fusion_version}
          />
          <DetailField
            label="Rule score"
            value={scores.rule_score}
          />
          <DetailField
            label="Statistical score"
            value={scores.statistical_score}
          />
          <DetailField
            label="Isolation Forest score"
            value={scores.isolation_forest_score}
          />
          <DetailField
            label="Autoencoder score"
            value={scores.autoencoder_score}
          />
          <DetailField
            label="AI consensus score"
            value={scores.ai_consensus_score}
          />
          <DetailField
            label="Critical allowed"
            value={
              scores.critical_allowed === undefined ||
              scores.critical_allowed === null
                ? null
                : String(scores.critical_allowed)
            }
          />
          <DetailField
            label="Feature record ID"
            value={scores.feature_record_id}
          />
          <DetailField
            label="Incident ID"
            value={incidentId}
          />
          <DetailField
            label="Incident status"
            value={incident?.status}
          />
          <DetailField
            label="Correlated event count"
            value={
              incident?.event_count ??
              incident?.event_ids?.length
            }
          />
          <DetailField
            label="SOC case status"
            value={incident?.soc_case_status}
          />
          <DetailField
            label="Mitigation status"
            value={incident?.mitigation_status}
          />

          <Alert severity="info" sx={{ mt: 2 }}>
            The engine and fusion version are displayed
            exactly as stored. Model provenance should be
            verified separately before relabeling old results.
          </Alert>
        </AccordionDetails>
      </Accordion>

      {/* RESPONSE WORKFLOW */}

      <Card
        sx={{
          background:
            "linear-gradient(135deg,#11241b,#111827)",
          borderColor: "rgba(34,197,94,0.3)",
        }}
      >
        <CardContent sx={{ p: 3 }}>
          <Stack
            direction={{ xs: "column", md: "row" }}
            justifyContent="space-between"
            alignItems={{ xs: "flex-start", md: "center" }}
            spacing={2}
          >
            <Box>
              <Typography variant="h6">
                Existing Response Workflow
              </Typography>

              <Typography
                sx={{ mt: 1, color: "#94a3b8" }}
              >
                {incident
                  ? `Correlation incident status: ${show(
                      incident.status
                    )}`
                  : "Incident relationship not verified"}
              </Typography>

              <Typography
                sx={{
                  color: "#64748b",
                  fontSize: 12,
                  mt: 1,
                  overflowWrap: "anywhere",
                }}
              >
                Incident ID: {show(incidentId)}
              </Typography>
            </Box>

            <Button
              variant="contained"
              startIcon={<ScienceRounded />}
              disabled={!incidentId}
              onClick={() =>
                navigate("/response-simulator", {
                  state: { incidentId },
                })
              }
            >
              Open Response Simulator
            </Button>
          </Stack>

          <Typography
            sx={{ color: "#94a3b8", fontSize: 12, mt: 2 }}
          >
            This button only navigates to the existing page.
            It does not execute a response or initiate
            an investigation. The simulator must independently
            validate the incident context.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}