import {
  useCallback,
  useEffect,
  useState,
} from "react";

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
  Typography,
} from "@mui/material";

import {
  PsychologyRounded,
  RefreshRounded,
  ScienceRounded,
  ShieldRounded,
} from "@mui/icons-material";

import {
  getUserSecurityAnalysisStatus,
  getUserSecurityThreat,
  startUserSecurityAnalysis,
} from "../api/sentinelApi";


const POLL_MS = 2000;
const MAX_POLLS = 45;


function list(value) {
  return Array.isArray(value)
    ? value
    : [];
}


function object(value) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  )
    ? value
    : {};
}


function show(value, fallback = "Not available") {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return fallback;
  }

  return String(value);
}


function pretty(value) {
  return show(value, "")
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
    .replace(/Powershell/g, "PowerShell");
}


function formatConfidence(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "Not reported";
  }

  const percent = number <= 1
    ? number * 100
    : number;

  return `${Math.round(percent * 10) / 10}%`;
}


function isNotFound(error) {
  return error?.response?.status === 404;
}


function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}


function statusColor(state) {
  switch (String(state || "").toUpperCase()) {
    case "READY":
      return "success";

    case "FAILED":
      return "error";

    case "PENDING":
    case "PROCESSING":
      return "info";

    default:
      return "default";
  }
}


function ActionRow({ item }) {
  const action = object(item);
  const target = object(action.target);

  return (
    <Box
      sx={{
        p: 1.4,
        borderRadius: 2,
        border: "1px solid #1e293b",
        background: "#0f172a",
      }}
    >
      <Typography
        sx={{
          fontWeight: 700,
          fontSize: 13,
        }}
      >
        {show(
          action.action_label ||
          pretty(action.action_type),
          "Simulated protection action",
        )}
      </Typography>

      {Object.keys(target).length > 0 && (
        <Typography
          sx={{
            color: "#94a3b8",
            fontSize: 11,
            mt: 0.6,
            overflowWrap: "anywhere",
          }}
        >
          Target: {JSON.stringify(target)}
        </Typography>
      )}
    </Box>
  );
}


export default function UserSecurityAIAnalysis({
  securityId,
  autoStart = true,
  compact = false,
  onSnapshot,
}) {
  const [snapshot, setSnapshot] = useState(null);
  const [analysisStatus, setAnalysisStatus] = useState(null);
  const [loading, setLoading] = useState(Boolean(securityId));
  const [error, setError] = useState("");
  const [runKey, setRunKey] = useState(0);


  const publishSnapshot = useCallback(
    (value) => {
      setSnapshot(value || null);

      if (
        value &&
        typeof onSnapshot === "function"
      ) {
        onSnapshot(value);
      }
    },
    [onSnapshot],
  );


  useEffect(
    () => {
      let active = true;

      async function loadReadySnapshot() {
        const value = await getUserSecurityThreat(
          securityId,
        );

        if (!active) {
          return null;
        }

        publishSnapshot(value);
        setAnalysisStatus({
          state: "READY",
          cached: true,
          snapshot_available: true,
        });
        setError("");
        setLoading(false);

        return value;
      }


      async function pollUntilDone() {
        for (
          let index = 0;
          index < MAX_POLLS;
          index += 1
        ) {
          if (!active) {
            return;
          }

          await sleep(POLL_MS);

          if (!active) {
            return;
          }

          const status = await getUserSecurityAnalysisStatus(
            securityId,
          );

          if (!active) {
            return;
          }

          setAnalysisStatus(status);

          const state = String(
            status?.state || "",
          ).toUpperCase();

          if (state === "READY") {
            await loadReadySnapshot();
            return;
          }

          if (state === "FAILED") {
            setError(
              status?.error ||
              "AI analysis could not be completed.",
            );
            setLoading(false);
            return;
          }
        }

        if (active) {
          setError(
            "AI analysis is taking longer than expected. You can retry without affecting the canonical threat details.",
          );
          setLoading(false);
        }
      }


      async function startAnalysis(force = false) {
        const started = await startUserSecurityAnalysis(
          securityId,
          {
            protectionMode: "RECOMMENDED",
            force,
          },
        );

        if (!active) {
          return;
        }

        setAnalysisStatus(started);

        const state = String(
          started?.state || "",
        ).toUpperCase();

        if (state === "READY") {
          await loadReadySnapshot();
          return;
        }

        await pollUntilDone();
      }


      async function initialise() {
        const forceRequested =
          runKey > 0;

        if (!securityId) {
          setLoading(false);
          return;
        }

        setLoading(true);
        setError("");

        try {
          await loadReadySnapshot();
          return;
        }
        catch (snapshotError) {
          if (!isNotFound(snapshotError)) {
            if (!active) {
              return;
            }

            setError(
              snapshotError?.response?.data?.detail ||
              snapshotError?.message ||
              "Unable to load AI security analysis.",
            );
            setLoading(false);
            return;
          }
        }

        if (!active) {
          return;
        }

        publishSnapshot(null);

        try {
          const status = await getUserSecurityAnalysisStatus(
            securityId,
          );

          if (!active) {
            return;
          }

          setAnalysisStatus(status);

          const state = String(
            status?.state || "",
          ).toUpperCase();

          if (state === "READY") {
            await loadReadySnapshot();
            return;
          }

          if (
            state === "PENDING" ||
            state === "PROCESSING"
          ) {
            await pollUntilDone();
            return;
          }

          if (state === "FAILED") {
            if (forceRequested) {
              await startAnalysis(true);
              return;
            }

            setError(
              status?.error ||
              "AI analysis was not completed.",
            );
            setLoading(false);
            return;
          }

          if (
            autoStart ||
            forceRequested
          ) {
            await startAnalysis(forceRequested);
            return;
          }

          setLoading(false);
        }
        catch (analysisError) {
          if (!active) {
            return;
          }

          setError(
            analysisError?.response?.data?.detail ||
            analysisError?.message ||
            "Unable to start AI security analysis.",
          );
          setLoading(false);
        }
      }


      initialise();


      return () => {
        active = false;
      };
    },
    [
      securityId,
      autoStart,
      publishSnapshot,
      runKey,
    ],
  );


  if (!securityId) {
    return null;
  }


  const risk = object(snapshot?.risk);
  const protection = object(snapshot?.protection);
  const response = object(snapshot?.response);
  const whyFlagged = list(snapshot?.why_flagged);
  const actions = list(response?.planned_actions);
  const state = String(
    analysisStatus?.state ||
    (snapshot ? "READY" : "NOT_STARTED"),
  ).toUpperCase();


  return (
    <Card
      sx={{
        mb: compact ? 2 : 3,
        borderColor: "rgba(167,139,250,0.35)",
        background:
          "linear-gradient(135deg,rgba(88,28,135,0.16),rgba(15,23,42,0.96))",
      }}
    >
      <CardContent
        sx={{
          p: compact ? 2.2 : 3,
        }}
      >
        <Stack
          direction={{
            xs: "column",
            sm: "row",
          }}
          justifyContent="space-between"
          alignItems={{
            xs: "flex-start",
            sm: "center",
          }}
          spacing={1.5}
        >
          <Stack
            direction="row"
            spacing={1}
            alignItems="center"
          >
            <PsychologyRounded
              sx={{
                color: "#a78bfa",
              }}
            />

            <Box>
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 750,
                }}
              >
                AI Security Analysis
              </Typography>

              <Typography
                sx={{
                  color: "#64748b",
                  fontSize: 11,
                  mt: 0.2,
                }}
              >
                Generated only when this threat is opened · cached after success
              </Typography>
            </Box>
          </Stack>

          <Chip
            size="small"
            color={statusColor(state)}
            variant="outlined"
            label={pretty(state || "Not Started")}
          />
        </Stack>


        {loading && (
          <Box
            sx={{
              mt: 2.5,
            }}
          >
            <Stack
              direction="row"
              spacing={1.2}
              alignItems="center"
            >
              <CircularProgress size={18} />

              <Typography
                sx={{
                  color: "#cbd5e1",
                  fontSize: 13,
                }}
              >
                {state === "PENDING"
                  ? "AI analysis is queued..."
                  : "Sentinel-X is analyzing this threat..."}
              </Typography>
            </Stack>

            <LinearProgress
              sx={{
                mt: 1.5,
                borderRadius: 2,
              }}
            />
          </Box>
        )}


        {!loading && error && (
          <Alert
            severity="warning"
            sx={{
              mt: 2,
            }}
            action={
              <Button
                color="inherit"
                size="small"
                startIcon={<RefreshRounded />}
                onClick={() => {
                  setError("");
                  setRunKey((value) => value + 1);
                }}
              >
                Retry
              </Button>
            }
          >
            {error}
            <Box
              sx={{
                mt: 0.5,
                fontSize: 11,
              }}
            >
              Canonical threat evidence remains available even when AI analysis fails.
            </Box>
          </Alert>
        )}


        {!loading && !snapshot && !error && !autoStart && (
          <Alert
            severity="info"
            sx={{
              mt: 2,
            }}
            action={
              <Button
                color="inherit"
                size="small"
                startIcon={<PsychologyRounded />}
                onClick={() => {
                  setRunKey((value) => value + 1);
                }}
              >
                Analyze
              </Button>
            }
          >
            No cached AI analysis exists for this threat yet.
          </Alert>
        )}


        {snapshot && (
          <Box
            sx={{
              mt: 2.5,
            }}
          >
            <Stack
              direction="row"
              gap={1}
              flexWrap="wrap"
            >
              <Chip
                size="small"
                icon={<ShieldRounded />}
                label={`Risk: ${pretty(risk.level) || "Not reported"}`}
              />

              <Chip
                size="small"
                variant="outlined"
                label={`Assessment: ${pretty(risk.assessment) || "Not reported"}`}
              />

              <Chip
                size="small"
                variant="outlined"
                label={`Confidence: ${formatConfidence(risk.confidence)}`}
              />

              <Chip
                size="small"
                variant="outlined"
                label={`Policy: ${pretty(protection.policy_decision) || "Not reported"}`}
              />
            </Stack>


            <Typography
              sx={{
                mt: 2,
                fontWeight: 800,
                fontSize: compact ? 17 : 20,
              }}
            >
              {show(snapshot.headline, "AI security analysis ready")}
            </Typography>

            <Typography
              sx={{
                mt: 1,
                color: "#cbd5e1",
                lineHeight: 1.7,
                fontSize: compact ? 13 : 14,
              }}
            >
              {show(snapshot.summary)}
            </Typography>


            {whyFlagged.length > 0 && (
              <Box
                sx={{
                  mt: 2,
                }}
              >
                <Typography
                  sx={{
                    fontWeight: 700,
                    fontSize: 13,
                  }}
                >
                  Why Sentinel-X flagged it
                </Typography>

                <Stack
                  spacing={0.8}
                  sx={{
                    mt: 1,
                  }}
                >
                  {whyFlagged.map((item, index) => (
                    <Typography
                      key={index}
                      sx={{
                        color: "#cbd5e1",
                        fontSize: 13,
                      }}
                    >
                      • {item}
                    </Typography>
                  ))}
                </Stack>
              </Box>
            )}


            <Divider
              sx={{
                my: 2,
              }}
            />


            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: {
                  xs: "1fr",
                  md: compact ? "1fr" : "repeat(2,1fr)",
                },
                gap: 2,
              }}
            >
              <Box>
                <Typography
                  sx={{
                    fontWeight: 700,
                    fontSize: 13,
                  }}
                >
                  Why it matters
                </Typography>

                <Typography
                  sx={{
                    mt: 0.7,
                    color: "#94a3b8",
                    fontSize: 12,
                    lineHeight: 1.6,
                  }}
                >
                  {show(snapshot.why_it_matters)}
                </Typography>
              </Box>

              <Box>
                <Typography
                  sx={{
                    fontWeight: 700,
                    fontSize: 13,
                  }}
                >
                  Uncertainty
                </Typography>

                <Typography
                  sx={{
                    mt: 0.7,
                    color: "#94a3b8",
                    fontSize: 12,
                    lineHeight: 1.6,
                  }}
                >
                  {show(snapshot.uncertainty_note)}
                </Typography>
              </Box>
            </Box>


            <Box
              sx={{
                mt: 2,
                p: 1.7,
                borderRadius: 2,
                border: "1px solid #1e293b",
                background: "#0f172a",
              }}
            >
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
              >
                <ScienceRounded
                  sx={{
                    color: "#60a5fa",
                    fontSize: 18,
                  }}
                />

                <Typography
                  sx={{
                    fontWeight: 700,
                    fontSize: 13,
                  }}
                >
                  AI Response Preview
                </Typography>
              </Stack>

              <Typography
                sx={{
                  mt: 1,
                  color: "#cbd5e1",
                  fontSize: 13,
                  lineHeight: 1.6,
                }}
              >
                {show(response.explanation)}
              </Typography>

              {response.selected_plan_id && (
                <Typography
                  sx={{
                    mt: 1,
                    color: "#94a3b8",
                    fontSize: 11,
                  }}
                >
                  Selected simulated plan: {response.selected_plan_id}
                </Typography>
              )}

              {actions.length > 0 && (
                <Stack
                  spacing={1}
                  sx={{
                    mt: 1.5,
                  }}
                >
                  {actions.map((item, index) => (
                    <ActionRow
                      key={`${item?.action_type || "action"}-${index}`}
                      item={item}
                    />
                  ))}
                </Stack>
              )}

              <Typography
                sx={{
                  mt: 1.5,
                  color: "#64748b",
                  fontSize: 11,
                  lineHeight: 1.5,
                }}
              >
                {show(
                  response.digital_twin_note,
                  protection.execution_message ||
                  "Simulation only. No real endpoint response has been executed.",
                )}
              </Typography>
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
