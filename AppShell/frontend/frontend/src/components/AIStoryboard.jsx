
import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Divider,
  LinearProgress,
  Stack,
  Typography,
} from "@mui/material";

import {
  PsychologyRounded,
  PlayArrowRounded,
  PauseRounded,
  SkipNextRounded,
  SkipPreviousRounded,
  ReplayRounded,
  ShieldRounded,
} from "@mui/icons-material";

import api from "../api/sentinelApi";

const SYNTHETIC_MODE =
  import.meta.env.VITE_SENTINEL_SYNTHETIC_LAB === "true";

const COMPONENTS = [
  ["process", "Process", "#a78bfa"],
  ["file", "File", "#38bdf8"],
  ["network", "Network", "#f59e0b"],
  ["persistence", "Registry", "#22c55e"],
  ["isolation_adjustment", "Isolation", "#fb7185"],
];

function object(value) {
  return value && typeof value === "object" &&
    !Array.isArray(value) ? value : {};
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function show(value) {
  return value === null ||
    value === undefined ||
    value === ""
    ? "Not reported"
    : String(value);
}

function fallbackScenes(decision) {
  const validation = object(
    decision?.evidence_validation
  );

  const counts = object(
    decision?.evidence_counts
  );

  const baseline = decision?.initial_risk_score;
  const components = object(
    decision?.baseline_risk_components
  );

  const ready =
    decision?.investigation_status === "COMPLETED" &&
    validation.passed === true;

  const scenes = [
    {
      kind: "EVIDENCE",
      focus: "endpoint",
      heading: "Understand the observations",
      text:
        `Virtual evidence contains ` +
        `${show(counts.processes)} process entities, ` +
        `${show(counts.network_connections)} network ` +
        `connections, ${show(counts.files)} files and ` +
        `${show(counts.registry_artifacts)} registry ` +
        `artifacts. These are not necessarily malicious.`,
      score: baseline,
      components,
      direction: {
        pace: "normal",
        emphasis: "action",
      },
    },
    {
      kind: "VALIDATION",
      focus: "endpoint",
      heading: "Check evidence reliability",
      text:
        `Investigation status: ` +
        `${show(decision?.investigation_status)}. ` +
        `Evidence passed: ` +
        `${validation.passed === true}. ` +
        list(validation.reasons).join(" "),
      score: baseline,
      components,
      direction: {
        pace: "normal",
        emphasis: "action",
      },
    },
  ];

  if (!ready || !list(decision?.ranked_plans).length) {
    scenes.push({
      kind: "BLOCKED",
      focus: "endpoint",
      heading: "Explain why simulation stops",
      text:
        "The backend did not establish an eligible " +
        "protection plan. No virtual response should " +
        "be presented as an approved action.",
      score: baseline,
      components,
      direction: {
        pace: "slow",
        emphasis: "action",
      },
    });

    return scenes;
  }

  const plan =
    object(decision?.best_plan).plan_id
      ? object(decision.best_plan)
      : list(decision.ranked_plans)[0];

  const frames = list(plan.playback);

  frames.forEach((frame) => {
    const type = String(
      frame.action_type || "BASELINE"
    );

    const focus =
      type.includes("PROCESS") ? "process" :
      type.includes("FILE") ? "file" :
      type.includes("NETWORK") ||
      type.includes("ISOLATE") ? "network" :
      type.includes("PERSISTENCE") ? "registry" :
      "endpoint";

    scenes.push({
      kind: "SIMULATION",
      focus,
      heading: type.replaceAll("_", " "),
      text:
        `Recorded virtual status: ` +
        `${show(frame.status)}. ` +
        `Simulator success: ` +
        `${frame.success === true}. ` +
        "No actual endpoint action occurred.",
      score: frame.risk_score,
      components: object(frame.risk_components),
      state: frame.state,
      direction: {
        pace: "normal",
        emphasis: "state",
      },
    });
  });

  scenes.push({
    kind: "REPORT",
    focus: "endpoint",
    heading: "Interpret the simulation",
    text:
      `${list(decision.ranked_plans).length} ` +
      "hypothetical plans were evaluated. " +
      "Modeled risk reduction is not proof " +
      "of real-world mitigation.",
    score: baseline,
    components,
    direction: {
      pace: "slow",
      emphasis: "risk",
    },
  });

  return scenes;
}

function RiskComponents({ values }) {
  const components = object(values);

  return (
    <Stack spacing={1.5}>
      {COMPONENTS.map(([key, title, color]) => {
        const value = Number(components[key]);

        if (
          components[key] === undefined ||
          !Number.isFinite(value)
        ) {
          return null;
        }

        return (
          <Box key={key}>
            <Stack
              direction="row"
              justifyContent="space-between"
              sx={{ mb: 0.5 }}
            >
              <Typography
                sx={{
                  color: "#cbd5e1",
                  fontSize: 12,
                }}
              >
                {title}
              </Typography>

              <Typography
                sx={{
                  color,
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                {value > 0 ? "+" : ""}
                {value}
              </Typography>
            </Stack>

            <LinearProgress
              variant="determinate"
              value={Math.min(
                Math.abs(value),
                100
              )}
              sx={{
                height: 8,
                borderRadius: 5,
                bgcolor: "#26354e",
                "& .MuiLinearProgress-bar": {
                  bgcolor: color,
                },
              }}
            />
          </Box>
        );
      })}
    </Stack>
  );
}

export default function AIStoryboard({
  incidentId,
  decision,
}) {
  const [remote, setRemote] = useState(null);
  const [loading, setLoading] = useState(false);
  const [position, setPosition] = useState(0);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    let active = true;

    setRemote(null);
    setPosition(0);
    setPlaying(false);

    // Never send real incident information to
    // the synthetic lab.
    if (
      !SYNTHETIC_MODE ||
      !String(incidentId).startsWith("LAB-")
    ) {
      return () => {
        active = false;
      };
    }

    setLoading(true);

    api.get(
      `/ai-storyboard/${encodeURIComponent(incidentId)}`
    ).then((response) => {
      if (
        active &&
        response.data?.incident_id === incidentId &&
        response.data?.synthetic === true
      ) {
        setRemote(response.data);
      }
    }).catch(() => {
      // Deterministic narration remains available.
    }).finally(() => {
      if (active) setLoading(false);
    });

    return () => {
      active = false;
    };
  }, [incidentId]);

  const localScenes = useMemo(
    () => fallbackScenes(decision),
    [decision]
  );

  const scenes = useMemo(
    () => remote && list(remote.scenes).length
      ? remote.scenes
      : localScenes,
    [remote, localScenes]
  );

  const safePosition = Math.min(
    position,
    Math.max(0, scenes.length - 1)
  );

  const scene = object(scenes[safePosition]);

  const pace = object(scene.direction).pace;

  const delay =
    pace === "slow" ? 4000 :
    pace === "fast" ? 1800 :
    2900;

  useEffect(() => {
    if (!playing || scenes.length < 2) {
      return undefined;
    }

    if (position >= scenes.length - 1) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setPosition((value) =>
        Math.min(value + 1, scenes.length - 1)
      );
    }, delay);

    return () => window.clearTimeout(timer);
  }, [playing, position, scenes.length, delay]);

  useEffect(() => {
    if (playing && position >= scenes.length - 1) {
      setPlaying(false);
    }
  }, [playing, position, scenes.length]);

  const focus = String(
    scene.focus || "endpoint"
  );

  const focusColor = {
    process: "#a78bfa",
    file: "#38bdf8",
    network: "#f59e0b",
    registry: "#22c55e",
    endpoint: "#60a5fa",
  }[focus] || "#60a5fa";

  const progress = scenes.length
    ? ((safePosition + 1) / scenes.length) * 100
    : 0;

  const llmActive =
    remote?.llm_provider === "LOCAL_OLLAMA";

  return (
    <Card
      sx={{
        mb: 3,
        borderColor: "rgba(96,165,250,0.35)",
        background:
          "linear-gradient(145deg,#101b30,#0c1423)",
      }}
    >
      <CardContent sx={{ p: { xs: 2, md: 3 } }}>
        <Stack
          direction={{
            xs: "column",
            md: "row",
          }}
          justifyContent="space-between"
          spacing={2}
          sx={{ mb: 2 }}
        >
          <Box>
            <Stack
              direction="row"
              alignItems="center"
              spacing={1}
            >
              <PsychologyRounded
                sx={{ color: "#a78bfa" }}
              />

              <Typography variant="h6">
                AI-Guided Simulation Storyboard
              </Typography>
            </Stack>

            <Typography
              sx={{
                mt: 0.6,
                color: "#94a3b8",
                fontSize: 12,
              }}
            >
              Evidence → Validation → Virtual response
              → Interpretation
            </Typography>
          </Box>

          <Stack
            direction="row"
            gap={1}
            flexWrap="wrap"
          >
            <Chip
              size="small"
              color="info"
              label="READ ONLY"
            />

            <Chip
              size="small"
              label={
                llmActive
                  ? "OLLAMA DIRECTED"
                  : "FACT-GROUNDED FALLBACK"
              }
            />

            {SYNTHETIC_MODE && (
              <Chip
                size="small"
                color="warning"
                label="SYNTHETIC LAB"
              />
            )}
          </Stack>
        </Stack>

        {loading && (
          <Alert severity="info" sx={{ mb: 2 }}>
            Preparing the local AI storyboard...
          </Alert>
        )}

        {remote?.validation_injected && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Evidence validation was injected by an
            isolated test fixture, not established by
            the production evidence validator.
          </Alert>
        )}

        <Stack
          direction="row"
          justifyContent="space-between"
          sx={{ mb: 1 }}
        >
          <Typography
            color="text.secondary"
            fontSize={12}
          >
            {show(scene.kind)}
          </Typography>

          <Typography fontWeight={700} fontSize={12}>
            Scene {safePosition + 1} / {scenes.length}
          </Typography>
        </Stack>

        <LinearProgress
          variant="determinate"
          value={progress}
          sx={{
            height: 8,
            borderRadius: 5,
            mb: 3,
          }}
        />

        <Box
          key={`${incidentId}-${safePosition}`}
          sx={{
            display: "grid",
            gridTemplateColumns: {
              xs: "1fr",
              md: "1.1fr 1fr",
            },
            gap: 3,
            animation: "sceneEnter 500ms ease-out",
            "@keyframes sceneEnter": {
              "0%": {
                opacity: 0,
                transform: "translateY(12px)",
              },
              "100%": {
                opacity: 1,
                transform: "translateY(0)",
              },
            },
          }}
        >
          <Box
            sx={{
              p: 3,
              borderRadius: 3,
              bgcolor: "rgba(15,23,42,0.85)",
              border: "1px solid #263952",
            }}
          >
            <Box
              sx={{
                height: 75,
                width: 75,
                borderRadius: "50%",
                border: `2px solid ${focusColor}`,
                display: "grid",
                placeItems: "center",
                mb: 2,
                color: focusColor,
                boxShadow:
                  `0 0 28px ${focusColor}35`,
                animation: "scenePulse 1.8s ease-in-out infinite",
                "@keyframes scenePulse": {
                  "0%,100%": {
                    transform: "scale(1)",
                    opacity: 0.85,
                  },
                  "50%": {
                    transform: "scale(1.06)",
                    opacity: 1,
                  },
                },
              }}
            >
              <ShieldRounded sx={{ fontSize: 34 }} />
            </Box>

            <Typography
              variant="h5"
              fontWeight={800}
              sx={{ mb: 1.5 }}
            >
              {show(scene.heading)}
            </Typography>

            <Typography
              sx={{
                color: "#cbd5e1",
                lineHeight: 1.8,
              }}
            >
              {show(scene.text)}
            </Typography>

            <Divider sx={{ my: 2 }} />

            <Typography
              sx={{
                color: "#94a3b8",
                fontSize: 12,
              }}
            >
              Focus: {focus.toUpperCase()}
            </Typography>

            <Typography
              sx={{
                mt: 1,
                color: "#94a3b8",
                fontSize: 12,
              }}
            >
              Presentation emphasis:{" "}
              {show(
                object(scene.direction).emphasis
              )}
            </Typography>
          </Box>

          <Box
            sx={{
              p: 3,
              borderRadius: 3,
              bgcolor: "#0f172a",
              border: "1px solid #263952",
            }}
          >
            <Typography fontWeight={700}>
              Recorded Virtual Data
            </Typography>

            <Stack
              direction="row"
              spacing={1}
              alignItems="baseline"
              sx={{ my: 2 }}
            >
              <Typography
                fontSize={38}
                fontWeight={800}
                color="#93c5fd"
              >
                {show(scene.score)}
              </Typography>

              <Typography
                color="text.secondary"
                fontSize={12}
              >
                heuristic points
              </Typography>
            </Stack>

            <RiskComponents
              values={scene.components}
            />

            <Typography
              sx={{
                color: "#94a3b8",
                mt: 2,
                fontSize: 12,
              }}
            >
              These values come from the simulation,
              not from LLM predictions.
            </Typography>
          </Box>
        </Box>

        <Stack
          direction="row"
          flexWrap="wrap"
          gap={1}
          justifyContent="center"
          sx={{ mt: 3 }}
        >
          <Button
            variant="outlined"
            disabled={safePosition === 0}
            startIcon={<SkipPreviousRounded />}
            onClick={() => {
              setPlaying(false);
              setPosition((v) => Math.max(0, v - 1));
            }}
          >
            Previous
          </Button>

          <Button
            variant="contained"
            startIcon={
              playing
                ? <PauseRounded />
                : <PlayArrowRounded />
            }
            disabled={
              scenes.length < 2 ||
              (
                !playing &&
                safePosition === scenes.length - 1
              )
            }
            onClick={() =>
              setPlaying((value) => !value)
            }
          >
            {playing ? "Pause" : "Play"}
          </Button>

          <Button
            variant="outlined"
            endIcon={<SkipNextRounded />}
            disabled={
              safePosition === scenes.length - 1
            }
            onClick={() => {
              setPlaying(false);
              setPosition((v) =>
                Math.min(v + 1, scenes.length - 1)
              );
            }}
          >
            Next
          </Button>

          <Button
            variant="outlined"
            startIcon={<ReplayRounded />}
            onClick={() => {
              setPlaying(false);
              setPosition(0);
            }}
          >
            Replay
          </Button>
        </Stack>

        <Alert severity="info" sx={{ mt: 3 }}>
          The LLM may direct pacing and presentation
          emphasis but cannot create events, change
          scores, select unrecorded actions or authorize
          responses.
        </Alert>
      </CardContent>
    </Card>
  );
}
