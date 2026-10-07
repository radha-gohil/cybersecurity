import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  useLocation,
  useNavigate,
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
  ExpandMoreRounded,
  PsychologyRounded,
  RefreshRounded,
  ScienceRounded,
  SearchRounded,
  ShieldRounded,
  TimelineRounded,
  WarningAmberRounded,
} from "@mui/icons-material";

import api from "../api/sentinelApi";


// ================================================================
// CONFIG
// ================================================================

const CONTRACT_VERSION =
  "sentinelx.security.v1";


// ================================================================
// BASIC HELPERS
// ================================================================

function object(
  value,
) {

  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  )
    ? value
    : {};
}


function list(
  value,
) {

  return Array.isArray(
    value,
  )
    ? value
    : [];
}


function show(
  value,
  fallback = "Not reported",
) {

  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {

    return fallback;
  }

  if (
    typeof value === "object"
  ) {

    return JSON.stringify(
      value,
    );
  }

  return String(
    value,
  );
}


function humanize(
  value,
) {

  return String(
    value || "",
  )
    .replace(
      /_/g,
      " ",
    )
    .replace(
      /\s+/g,
      " ",
    )
    .trim()
    .toLowerCase()
    .replace(
      /\b\w/g,
      (letter) =>
        letter.toUpperCase(),
    )
    .replace(
      /Soc/g,
      "Security",
    )
    .replace(
      /Powershell/g,
      "PowerShell",
    );
}


function userFacingText(
  value,
) {

  return String(
    value || "",
  )
    .replace(
      /No qualifying authoritative event evidence\./gi,
      (
        "No production-authoritative event evidence was "
        +
        "established. Recorded validation evidence remains "
        +
        "available for read-only investigation."
      ),
    )
    .replace(
      /analyst investigation/gi,
      "security investigation",
    )
    .replace(
      /analyst review/gi,
      "security review",
    )
    .replace(
      /analyst validation/gi,
      "evidence validation",
    )
    .replace(
      /human approval/gi,
      "explicit protection authorization",
    )
    .replace(
      /\bSOC\b/gi,
      "security",
    )
    .replace(
      /containment authorization/gi,
      "protection authorization",
    )
    .replace(
      /real containment/gi,
      "real protection action",
    )
    .replace(
      /containment/gi,
      "protection",
    );
}


// ================================================================
// COLORS
// ================================================================

function severityColor(
  severity,
) {

  switch (
    String(
      severity || "",
    ).toUpperCase()
  ) {

    case "CRITICAL":

      return "#ef4444";

    case "HIGH":

      return "#f97316";

    case "MEDIUM":

      return "#f59e0b";

    case "LOW":

      return "#3b82f6";

    case "INFO":

      return "#22c55e";

    default:

      return "#94a3b8";
  }
}


// ================================================================
// FRIENDLY LABELS
// ================================================================

function friendlyDecision(
  value,
) {

  const normalized =
    String(
      value || "",
    ).toUpperCase();

  const mapping = {

    INVESTIGATE:
      "Investigate Further",

    CONTINUE_ANALYSIS:
      "Continue Analysis",

    MONITOR:
      "Monitor",

    RESPONSE_REVIEW:
      "Protection Review",

    RESPONSE_RECOMMENDED:
      "Protection Recommended",

    CONTAINMENT_RECOMMENDED:
      "Protection Recommended",
  };

  return (
    mapping[
      normalized
    ]
    ||
    humanize(
      value ||
      "Not reported",
    )
  );
}


function friendlySecurityState(
  value,
) {

  const normalized =
    String(
      value || "",
    ).toUpperCase();

  const mapping = {

    CRITICAL_RESPONSE_REVIEW:
      "Critical — Protection Review",

    RESPONSE_REVIEW:
      "Protection Review",

    EVIDENCE_REVIEW_REQUIRED:
      "More Evidence Needed",

    SECURITY_REVIEW:
      "Security Review",
  };

  return (
    mapping[
      normalized
    ]
    ||
    humanize(
      value ||
      "Not reported",
    )
  );
}


function recommendationLabel(
  value,
) {

  const normalized =
    String(
      value || "",
    ).toUpperCase();

  const mapping = {

    MONITOR_INCIDENT:
      "Continue Monitoring",

    INVESTIGATE_INCIDENT:
      "Continue Investigation",

    PROCESS_TERMINATION_REVIEW:
      "Simulate Stopping Suspicious Process",

    NETWORK_BLOCK_REVIEW:
      "Simulate Blocking Network Connection",

    PERSISTENCE_REMEDIATION_REVIEW:
      "Simulate Removing Persistence",

    QUARANTINE_REVIEW:
      "Simulate File Quarantine",

    DEVICE_ISOLATION_REVIEW:
      "Simulate Device Isolation",

    ENDPOINT_ISOLATION_REVIEW:
      "Simulate Device Isolation",
  };

  return (
    mapping[
      normalized
    ]
    ||
    humanize(
      value ||
      "Protection Recommendation",
    )
  );
}


// ================================================================
// TIME
// ================================================================

function formatTime(
  value,
) {

  if (!value) {

    return "Not reported";
  }

  const parsed =
    new Date(
      value,
    );

  if (
    Number.isNaN(
      parsed.getTime(),
    )
  ) {

    return String(
      value,
    );
  }

  return (
    parsed.toLocaleString()
  );
}


// ================================================================
// METRIC CARD
// ================================================================

function MetricCard({
  label,
  value,
  subtext,
  color = "#60a5fa",
}) {

  return (

    <Card>

      <CardContent
        sx={{
          p: 2.5,
        }}
      >

        <Typography
          sx={{
            color:
              "#94a3b8",

            fontSize:
              12,
          }}
        >

          {label}

        </Typography>


        <Typography
          sx={{
            fontSize:
              26,

            fontWeight:
              800,

            color,

            mt:
              0.7,

            overflowWrap:
              "anywhere",
          }}
        >

          {
            show(
              value,
              "—",
            )
          }

        </Typography>


        {
          subtext
          &&
          (

            <Typography
              sx={{
                color:
                  "#64748b",

                fontSize:
                  11,

                mt:
                  0.8,

                lineHeight:
                  1.5,
              }}
            >

              {subtext}

            </Typography>
          )
        }

      </CardContent>

    </Card>
  );
}


// ================================================================
// EVIDENCE METRIC
// ================================================================

function EvidenceMetric({
  label,
  value,
}) {

  return (

    <Box
      sx={{
        p:
          1.8,

        border:
          "1px solid #1e293b",

        borderRadius:
          2,

        background:
          "#0f172a",
      }}
    >

      <Typography
        sx={{
          color:
            "#94a3b8",

          fontSize:
            11,
        }}
      >

        {label}

      </Typography>


      <Typography
        sx={{
          mt:
            0.6,

          fontWeight:
            750,

          fontSize:
            20,
        }}
      >

        {
          show(
            value,
            "0",
          )
        }

      </Typography>

    </Box>
  );
}


// ================================================================
// FINDINGS
// ================================================================

function FindingList({
  findings,
}) {

  if (
    !findings.length
  ) {

    return (

      <Alert
        severity="info"
      >

        No investigation findings were returned.

      </Alert>
    );
  }


  return (

    <Stack
      spacing={1.2}
    >

      {
        findings.map(
          (
            finding,
            index,
          ) => (

            <Box

              key={
                index
              }

              sx={{
                p:
                  1.6,

                borderRadius:
                  2,

                background:
                  "#0f172a",

                border:
                  "1px solid #1e293b",
              }}

            >

              <Typography
                sx={{
                  color:
                    "#cbd5e1",

                  lineHeight:
                    1.65,
                }}
              >

                {
                  userFacingText(
                    typeof finding ===
                      "string"
                      ? finding
                      : JSON.stringify(
                          finding,
                        ),
                  )
                }

              </Typography>

            </Box>
          ),
        )
      }

    </Stack>
  );
}


// ================================================================
// TIMELINE
// ================================================================

function TimelineEntry({
  event,
  index,
}) {

  const category =
    String(
      event?.event_category ||
      event?.category ||
      "OTHER",
    ).toUpperCase();


  return (

    <Box
      sx={{
        display:
          "flex",

        gap:
          1.5,

        pb:
          2,

        mb:
          1.5,

        borderBottom:
          "1px solid #1e293b",
      }}
    >

      <Box
        sx={{
          width:
            28,

          height:
            28,

          borderRadius:
            "50%",

          background:
            "#13233c",

          color:
            "#60a5fa",

          display:
            "flex",

          alignItems:
            "center",

          justifyContent:
            "center",

          fontWeight:
            750,

          fontSize:
            12,

          flexShrink:
            0,
        }}
      >

        {
          index + 1
        }

      </Box>


      <Box
        sx={{
          flex:
            1,

          minWidth:
            0,
        }}
      >

        <Stack

          direction="row"

          spacing={1}

          flexWrap="wrap"

          useFlexGap

          alignItems="center"

        >

          <Typography
            sx={{
              fontWeight:
                700,
            }}
          >

            {
              humanize(
                event?.description ||
                event?.event_type ||
                "Recorded Event",
              )
            }

          </Typography>


          <Chip

            label={
              category
            }

            size="small"

            variant="outlined"

          />

        </Stack>


        <Typography
          sx={{
            color:
              "#94a3b8",

            fontSize:
              12,

            mt:
              0.5,
          }}
        >

          {
            show(
              event?.event_id,
            )
          }

        </Typography>


        <Typography
          sx={{
            color:
              "#64748b",

            fontSize:
              11,

            mt:
              0.4,
          }}
        >

          {
            formatTime(
              event?.timestamp,
            )
          }

        </Typography>

      </Box>

    </Box>
  );
}


// ================================================================
// DETECTION EVIDENCE
// ================================================================

function DetectionCard({
  detection,
}) {

  const severity =
    String(
      detection?.severity ||
      "INFO",
    ).toUpperCase();


  const color =
    severityColor(
      severity,
    );


  return (

    <Box
      sx={{
        p:
          1.7,

        borderRadius:
          2,

        background:
          "#0f172a",

        border:
          "1px solid #1e293b",
      }}
    >

      <Stack

        direction={{
          xs:
            "column",

          md:
            "row",
        }}

        justifyContent="space-between"

        spacing={1}

      >

        <Box>

          <Typography
            sx={{
              fontWeight:
                700,
            }}
          >

            {
              humanize(
                detection
                  ?.threat_type ||
                detection
                  ?.engine ||
                "Security Detection",
              )
            }

          </Typography>


          <Typography
            sx={{
              color:
                "#94a3b8",

              fontSize:
                12,

              mt:
                0.4,
            }}
          >

            {
              show(
                detection?.engine,
              )
            }

            {" · "}

            {
              show(
                detection?.event_id,
              )
            }

          </Typography>

        </Box>


        <Stack

          direction="row"

          spacing={1}

          flexWrap="wrap"

          useFlexGap

        >

          <Chip

            label={
              severity
            }

            size="small"

            variant="outlined"

            sx={{
              color,
            }}

          />


          <Chip

            label={
              (
                `Risk ${
                  show(
                    detection
                      ?.risk_score,
                    "—",
                  )
                }/100`
              )
            }

            size="small"

            variant="outlined"

          />


          {
            detection
              ?.confidence !==
              null
            &&
            detection
              ?.confidence !==
              undefined
            &&
            (

              <Chip

                label={
                  (
                    `Confidence ${
                      Math.round(
                        Number(
                          detection
                            .confidence,
                        )
                        *
                        1000,
                      )
                      /
                      10
                    }%`
                  )
                }

                size="small"

                variant="outlined"

              />
            )
          }

        </Stack>

      </Stack>

    </Box>
  );
}


// ================================================================
// RECOMMENDATION
// ================================================================

function RecommendationCard({
  item,
}) {

  const priority =
    String(
      item?.priority ||
      "INFO",
    ).toUpperCase();


  return (

    <Box
      sx={{
        p:
          1.7,

        borderRadius:
          2,

        background:
          "#0f172a",

        border:
          "1px solid #1e293b",
      }}
    >

      <Stack

        direction={{
          xs:
            "column",

          sm:
            "row",
        }}

        justifyContent="space-between"

        spacing={1}

      >

        <Typography
          sx={{
            fontWeight:
              700,
          }}
        >

          {
            recommendationLabel(
              item?.action,
            )
          }

        </Typography>


        <Chip

          label={
            priority
          }

          size="small"

          variant="outlined"

          sx={{
            color:
              severityColor(
                priority,
              ),
          }}

        />

      </Stack>


      <Typography
        sx={{
          color:
            "#94a3b8",

          mt:
            0.8,

          lineHeight:
            1.6,
        }}
      >

        {
          userFacingText(
            show(
              item?.reason,
            ),
          )
        }

      </Typography>


      <Typography
        sx={{
          color:
            "#64748b",

          mt:
            0.8,

          fontSize:
            11,
        }}
      >

        Advisory only · No endpoint action executed

      </Typography>

    </Box>
  );
}


// ================================================================
// TECHNICAL AGENT DECISION
// ================================================================

function AgentDecisionCard({
  decision,
}) {

  const severity =
    String(
      decision?.severity ||
      "INFO",
    ).toUpperCase();


  return (

    <Box
      sx={{
        p:
          1.7,

        borderRadius:
          2,

        background:
          "#0f172a",

        border:
          "1px solid #1e293b",
      }}
    >

      <Stack

        direction={{
          xs:
            "column",

          md:
            "row",
        }}

        justifyContent="space-between"

        spacing={1}

      >

        <Box>

          <Typography
            sx={{
              fontWeight:
                700,
            }}
          >

            {
              show(
                decision?.agent,
                "Agent",
              )
            }

          </Typography>


          <Typography
            sx={{
              color:
                "#94a3b8",

              fontSize:
                12,

              mt:
                0.4,
            }}
          >

            {
              friendlyDecision(
                decision?.decision,
              )
            }

          </Typography>

        </Box>


        <Stack
          direction="row"
          spacing={1}
        >

          <Chip

            label={
              severity
            }

            size="small"

            variant="outlined"

            sx={{
              color:
                severityColor(
                  severity,
                ),
            }}

          />


          <Chip

            label="Confidence not calibrated"

            size="small"

            variant="outlined"

          />

        </Stack>

      </Stack>


      <Typography
        sx={{
          mt:
            1.2,

          color:
            "#cbd5e1",

          lineHeight:
            1.6,
        }}
      >

        {
          userFacingText(
            show(
              decision?.reason,
              "No technical explanation recorded.",
            ),
          )
        }

      </Typography>

    </Box>
  );
}


// ================================================================
// PAGE
// ================================================================

export default function AISecurity() {

  const navigate =
    useNavigate();


  const location =
    useLocation();


  const requestedIncidentId =
    String(
      location.state
        ?.incidentId ||
      "",
    );


  const [
    incidents,
    setIncidents,
  ] =
    useState(
      [],
    );


  const [
    incidentId,
    setIncidentId,
  ] =
    useState(
      requestedIncidentId,
    );


  const [
    investigationData,
    setInvestigationData,
  ] =
    useState(
      null,
    );


  const [
    loading,
    setLoading,
  ] =
    useState(
      true,
    );


  const [
    error,
    setError,
  ] =
    useState(
      "",
    );


  // ==============================================================
  // LOAD CANONICAL INCIDENT LIST
  // ==============================================================

  const loadIncidentList =
    useCallback(
      async () => {

        const response =
          await api.get(
            "/security/incidents",
            {
              params: {
                limit:
                  100,
              },
            },
          );


        const payload =
          response.data ||
          {};


        if (
          payload
            .schema_version !==
          CONTRACT_VERSION
        ) {

          throw new Error(
            (
              "Unexpected canonical "
              +
              "security contract version."
            ),
          );
        }


        const rows =
          list(
            payload.incidents,
          );


        setIncidents(
          rows,
        );


        setIncidentId(
          (
            current,
          ) => {

            if (
              current
              &&
              rows.some(
                (
                  item,
                ) =>
                  String(
                    item
                      .incident_id,
                  )
                  ===
                  String(
                    current,
                  ),
              )
            ) {

              return current;
            }


            if (
              requestedIncidentId
              &&
              rows.some(
                (
                  item,
                ) =>
                  String(
                    item
                      .incident_id,
                  )
                  ===
                  requestedIncidentId,
              )
            ) {

              return (
                requestedIncidentId
              );
            }


            const fullChain =
              rows.find(
                (
                  item,
                ) =>
                  item
                    .incident_id
                  ===
                  "SYNTH-INC-FULL-CHAIN",
              );


            if (
              fullChain
            ) {

              return (
                fullChain
                  .incident_id
              );
            }


            return (
              rows[0]
                ?.incident_id
              ||
              ""
            );
          },
        );
      },

      [
        requestedIncidentId,
      ],
    );


  // ==============================================================
  // LOAD CANONICAL INVESTIGATION
  // ==============================================================

  const loadInvestigation =
    useCallback(
      async (
        id,
      ) => {

        if (!id) {

          return;
        }


        setLoading(
          true,
        );


        setError(
          "",
        );


        try {

          const response =
            await api.get(
              (
                "/security/incidents/"
                +
                `${encodeURIComponent(
                  id,
                )}`
                +
                "/investigation"
              ),
            );


          const payload =
            response.data ||
            {};


          if (
            payload
              .schema_version !==
            CONTRACT_VERSION
          ) {

            throw new Error(
              (
                "Unexpected canonical "
                +
                "investigation contract version."
              ),
            );
          }


          if (
            String(
              payload
                ?.incident
                ?.incident_id ||
              "",
            )
            !==
            String(
              id,
            )
          ) {

            throw new Error(
              (
                "Investigation incident "
                +
                "identity mismatch."
              ),
            );
          }


          setInvestigationData(
            payload,
          );

        } catch (
          loadError
        ) {

          setInvestigationData(
            null,
          );


          setError(
            loadError
              ?.response
              ?.data
              ?.detail
            ||
            loadError
              ?.message
            ||
            (
              "Unable to load the "
              +
              "canonical security investigation."
            ),
          );

        } finally {

          setLoading(
            false,
          );
        }
      },

      [],
    );


  // ==============================================================
  // INITIAL LIST
  // ==============================================================

  useEffect(
    () => {

      let active =
        true;


      async function start() {

        try {

          await loadIncidentList();

        } catch (
          loadError
        ) {

          if (
            active
          ) {

            setError(
              loadError
                ?.response
                ?.data
                ?.detail
              ||
              loadError
                ?.message
              ||
              (
                "Unable to load "
                +
                "security incidents."
              ),
            );


            setLoading(
              false,
            );
          }
        }
      }


      start();


      return (
        () => {

          active =
            false;
        }
      );

    },

    [
      loadIncidentList,
    ],
  );


  // ==============================================================
  // INCIDENT CHANGE
  // ==============================================================

  useEffect(
    () => {

      if (
        incidentId
      ) {

        loadInvestigation(
          incidentId,
        );
      }

    },

    [
      incidentId,
      loadInvestigation,
    ],
  );


  // ==============================================================
  // CANONICAL OBJECTS
  // ==============================================================

  const incident =
    object(
      investigationData
        ?.incident,
    );


  const investigation =
    object(
      investigationData
        ?.investigation,
    );


  const risk =
    object(
      investigation
        .risk,
    );


  const validation =
    object(
      investigationData
        ?.evidence_validation,
    );


  const boundaries =
    object(
      investigationData
        ?.evidence_boundaries,
    );


  const observed =
    object(
      boundaries.observed,
    );


  const findings =
    list(
      investigationData
        ?.findings,
    );


  const inferred =
    list(
      boundaries.inferred,
    );


  const unknown =
    list(
      boundaries.unknown,
    );


  const recommendations =
    list(
      investigationData
        ?.recommendations
        ?.items,
    );


  const detections =
    list(
      investigationData
        ?.detections,
    );


  const timeline =
    list(
      investigationData
        ?.timeline,
    );


  const consensus =
    object(
      investigationData
        ?.consensus,
    );


  const technical =
    object(
      investigationData
        ?.technical,
    );


  const safety =
    object(
      investigationData
        ?.safety,
    );


  const agentDecisions =
    list(
      technical
        .agent_decisions,
    );


  const reportSummary =
    object(
      technical
        .report_summary,
    );


  const entitySummary =
    object(
      observed
        .entity_summary,
    );


  const evidenceSummary =
    object(
      observed
        .evidence_summary,
    );


  const categories =
    list(
      observed.categories,
    ).length
      ? list(
          observed.categories,
        )
      : list(
          incident.categories,
        );


  const riskScore =
    risk.score;


  const riskLevel =
    risk.level ||
    "INFO";


  const incidentTitle =
    incident
      .display_title
    ||
    incident.title
    ||
    "Security Incident";


  const analysisStatus =
    investigation.status ||
    "UNKNOWN";


  // ==============================================================
  // LOADING
  // ==============================================================

  if (
    loading
    &&
    !investigationData
  ) {

    return (

      <Box
        sx={{
          py:
            8,

          textAlign:
            "center",
        }}
      >

        <CircularProgress />


        <Typography
          sx={{
            mt:
              2,
          }}
        >

          Loading canonical AI investigation...

        </Typography>

      </Box>
    );
  }


  // ==============================================================
  // RENDER
  // ==============================================================

  return (

    <Box>

      {/* ========================================================= */}
      {/* HEADER */}
      {/* ========================================================= */}

      <Stack

        direction={{
          xs:
            "column",

          lg:
            "row",
        }}

        justifyContent="space-between"

        alignItems={{
          xs:
            "stretch",

          lg:
            "center",
        }}

        spacing={2}

        sx={{
          mb:
            3,
        }}

      >

        <Box>

          <Typography
            variant="h4"
            sx={{
              fontWeight:
                800,
            }}
          >

            AI Investigation

          </Typography>


          <Typography
            sx={{
              color:
                "#94a3b8",

              mt:
                0.6,
            }}
          >

            Evidence-grounded, read-only investigation of recorded security incidents.

          </Typography>

        </Box>


        <Stack

          direction={{
            xs:
              "column",

            sm:
              "row",
          }}

          spacing={1.2}

        >

          <FormControl

            size="small"

            sx={{
              minWidth:
                360,
            }}

          >

            <InputLabel>

              Security incident

            </InputLabel>


            <Select

              label="Security incident"

              value={
                incidentId
              }

              onChange={
                (
                  event,
                ) =>
                  setIncidentId(
                    event.target.value,
                  )
              }

            >

              {
                incidents.map(
                  (
                    item,
                  ) => (

                    <MenuItem

                      key={
                        item.incident_id
                      }

                      value={
                        String(
                          item.incident_id,
                        )
                      }

                    >

                      {
                        item
                          .display_title
                        ||
                        item
                          .title
                      }

                      {" · "}

                      {
                        show(
                          item.severity,
                        )
                      }

                      {" · "}

                      {
                        show(
                          item.event_count,
                          0,
                        )
                      }

                      {" events"}

                    </MenuItem>
                  ),
                )
              }

            </Select>

          </FormControl>


          <Button

            variant="outlined"

            startIcon={
              <RefreshRounded />
            }

            disabled={
              !incidentId ||
              loading
            }

            onClick={
              () =>
                loadInvestigation(
                  incidentId,
                )
            }

          >

            Re-run Analysis

          </Button>

        </Stack>

      </Stack>


      {
        error
        &&
        (

          <Alert
            severity="error"
            sx={{
              mb:
                2,
            }}
          >

            {error}

          </Alert>
        )
      }


      {
        !incidentId
        &&
        (

          <Alert
            severity="info"
          >

            No user-visible security incident is available.

          </Alert>
        )
      }


      {
        investigationData
        &&
        (

          <>

            {/* ================================================= */}
            {/* INCIDENT SUMMARY */}
            {/* ================================================= */}

            <Card
              sx={{
                mb:
                  3,

                background:
                  "linear-gradient(135deg,#161326,#111827)",

                borderColor:
                  "rgba(139,92,246,0.35)",
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Stack

                  direction={{
                    xs:
                      "column",

                    md:
                      "row",
                  }}

                  justifyContent="space-between"

                  spacing={2}

                >

                  <Stack

                    direction="row"

                    spacing={2}

                    alignItems="center"

                  >

                    <Box
                      sx={{
                        width:
                          56,

                        height:
                          56,

                        borderRadius:
                          2,

                        display:
                          "flex",

                        alignItems:
                          "center",

                        justifyContent:
                          "center",

                        background:
                          "rgba(139,92,246,0.15)",

                        color:
                          "#a78bfa",

                        flexShrink:
                          0,
                      }}
                    >

                      <PsychologyRounded
                        sx={{
                          fontSize:
                            34,
                        }}
                      />

                    </Box>


                    <Box>

                      <Typography
                        variant="h6"
                        sx={{
                          fontWeight:
                            750,
                        }}
                      >

                        {incidentTitle}

                      </Typography>


                      <Typography
                        sx={{
                          color:
                            "#94a3b8",

                          fontSize:
                            12,

                          mt:
                            0.5,
                        }}
                      >

                        Incident
                        {" "}
                        {
                          show(
                            incident
                              .incident_id,
                          )
                        }

                      </Typography>

                    </Box>

                  </Stack>


                  <Stack

                    direction="row"

                    spacing={1}

                    flexWrap="wrap"

                    useFlexGap

                  >

                    <Chip

                      label={
                        humanize(
                          analysisStatus,
                        )
                      }

                      color={
                        analysisStatus ===
                          "COMPLETED"
                          ? "success"
                          : "warning"
                      }

                      variant="outlined"

                    />


                    <Chip

                      label={
                        show(
                          incident.severity,
                        )
                      }

                      sx={{
                        color:
                          severityColor(
                            incident.severity,
                          ),
                      }}

                      variant="outlined"

                    />


                    {
                      validation
                        .validation_only
                      &&
                      (

                        <Chip

                          label="VALIDATION ONLY"

                          variant="outlined"

                        />
                      )
                    }


                    <Chip

                      label="READ ONLY"

                      variant="outlined"

                    />

                  </Stack>

                </Stack>


                <Alert
                  severity="info"
                  sx={{
                    mt:
                      2,
                  }}
                >

                  This investigation reads persisted Sentinel-X
                  evidence only. It does not authorize or execute
                  a real endpoint protection action.

                </Alert>

              </CardContent>

            </Card>


            {/* ================================================= */}
            {/* METRICS */}
            {/* ================================================= */}

            <Box
              sx={{
                display:
                  "grid",

                gridTemplateColumns:
                  {

                    xs:
                      "1fr",

                    sm:
                      "repeat(2,minmax(0,1fr))",

                    lg:
                      "repeat(4,minmax(0,1fr))",
                  },

                gap:
                  2,

                mb:
                  3,
              }}
            >

              <MetricCard

                label="Investigation Risk"

                value={
                  riskScore ===
                    null ||
                  riskScore ===
                    undefined
                    ? "—"
                    : `${riskScore} / 100`
                }

                color={
                  severityColor(
                    riskLevel,
                  )
                }

                subtext={
                  (
                    `${show(
                      riskLevel,
                    )} review priority — `
                    +
                    "not an attack probability"
                  )
                }

              />


              <MetricCard

                label="Current Recommendation"

                value={
                  friendlyDecision(
                    investigation
                      .final_decision,
                  )
                }

                color="#a78bfa"

                subtext="Advisory investigation result"

              />


              <MetricCard

                label="Security State"

                value={
                  friendlySecurityState(
                    investigation
                      .security_state,
                  )
                }

                color="#60a5fa"

                subtext="Current read-only investigation state"

              />


              <MetricCard

                label="Evidence Coverage"

                value={
                  `${categories.length} categories`
                }

                color="#22c55e"

                subtext={
                  (
                    `${show(
                      observed
                        .timeline_event_count,
                      0,
                    )} recorded events · `
                    +
                    `${show(
                      observed
                        .stored_detection_count,
                      0,
                    )} stored detections`
                  )
                }

              />

            </Box>


            {/* ================================================= */}
            {/* RISK ASSESSMENT */}
            {/* ================================================= */}

            <Card
              sx={{
                mb:
                  3,
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Stack

                  direction={{
                    xs:
                      "column",

                    md:
                      "row",
                  }}

                  justifyContent="space-between"

                  spacing={2}

                >

                  <Box>

                    <Typography
                      variant="h6"
                    >

                      Investigation Risk Assessment

                    </Typography>


                    <Typography
                      sx={{
                        color:
                          "#94a3b8",

                        mt:
                          0.6,

                        maxWidth:
                          850,
                      }}
                    >

                      The investigation risk score represents
                      evidence-grounded review priority. It is
                      separate from detector risk and Digital Twin
                      heuristic risk.

                    </Typography>

                  </Box>


                  <Chip

                    label={
                      show(
                        riskLevel,
                      )
                    }

                    variant="outlined"

                    sx={{
                      color:
                        severityColor(
                          riskLevel,
                        ),
                    }}

                  />

                </Stack>


                {
                  Number.isFinite(
                    Number(
                      riskScore,
                    ),
                  )
                  &&
                  (

                    <LinearProgress

                      variant="determinate"

                      value={
                        Math.max(
                          0,
                          Math.min(
                            100,
                            Number(
                              riskScore,
                            ),
                          ),
                        )
                      }

                      sx={{
                        height:
                          9,

                        borderRadius:
                          3,

                        mt:
                          2,

                        background:
                          "#1e293b",
                      }}

                    />
                  )
                }


                <Box
                  sx={{
                    display:
                      "grid",

                    gridTemplateColumns:
                      {

                        xs:
                          "1fr",

                        sm:
                          "repeat(2,minmax(0,1fr))",

                        lg:
                          "repeat(4,minmax(0,1fr))",
                      },

                    gap:
                      1.5,

                    mt:
                      2,
                  }}
                >

                  <EvidenceMetric

                    label="Qualifying Events"

                    value={
                      validation
                        .qualifying_event_count
                    }

                  />


                  <EvidenceMetric

                    label="Stored Detections"

                    value={
                      validation
                        .stored_detection_count
                    }

                  />


                  <EvidenceMetric

                    label="Strong Detections"

                    value={
                      validation
                        .strong_detection_count
                    }

                  />


                  <EvidenceMetric

                    label="Cross-Category"

                    value={
                      validation
                        .cross_category_corroboration
                        ? "YES"
                        : "NO"
                    }

                  />

                </Box>


                <Typography
                  sx={{
                    color:
                      "#64748b",

                    fontSize:
                      11,

                    mt:
                      1.5,
                  }}
                >

                  Risk semantics:
                  {" "}
                  {
                    show(
                      risk.semantics,
                    )
                  }

                </Typography>

              </CardContent>

            </Card>


            {/* ================================================= */}
            {/* EVIDENCE BOUNDARIES */}
            {/* ================================================= */}

            <Card
              sx={{
                mb:
                  3,
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Stack

                  direction="row"

                  spacing={1}

                  alignItems="center"

                >

                  <ShieldRounded
                    sx={{
                      color:
                        "#22c55e",
                    }}
                  />


                  <Typography
                    variant="h6"
                  >

                    Evidence Boundaries

                  </Typography>

                </Stack>


                <Box
                  sx={{
                    display:
                      "grid",

                    gridTemplateColumns:
                      {

                        xs:
                          "1fr",

                        lg:
                          "repeat(3,minmax(0,1fr))",
                      },

                    gap:
                      1.5,

                    mt:
                      2,
                  }}
                >

                  <Box
                    sx={{
                      p:
                        2,

                      borderRadius:
                        2,

                      background:
                        "#0f172a",

                      border:
                        "1px solid #1e293b",
                    }}
                  >

                    <Typography
                      sx={{
                        fontWeight:
                          750,

                        color:
                          "#22c55e",
                      }}
                    >

                      Observed

                    </Typography>


                    <Typography
                      sx={{
                        mt:
                          1,

                        color:
                          "#cbd5e1",

                        lineHeight:
                          1.65,
                      }}
                    >

                      {
                        show(
                          observed
                            .timeline_event_count,
                          0,
                        )
                      }

                      {" recorded event(s), "}

                      {
                        show(
                          observed
                            .stored_detection_count,
                          0,
                        )
                      }

                      {" stored detection(s), across "}

                      {
                        categories.length
                      }

                      {" evidence categories."}

                    </Typography>

                  </Box>


                  <Box
                    sx={{
                      p:
                        2,

                      borderRadius:
                        2,

                      background:
                        "#0f172a",

                      border:
                        "1px solid #1e293b",
                    }}
                  >

                    <Typography
                      sx={{
                        fontWeight:
                          750,

                        color:
                          "#60a5fa",
                      }}
                    >

                      Investigation Findings

                    </Typography>


                    <Typography
                      sx={{
                        mt:
                          1,

                        color:
                          "#cbd5e1",

                        lineHeight:
                          1.65,
                      }}
                    >

                      {
                        inferred.length
                      }

                      {" evidence-grounded finding(s) or interpretation statements were returned."}

                    </Typography>

                  </Box>


                  <Box
                    sx={{
                      p:
                        2,

                      borderRadius:
                        2,

                      background:
                        "#0f172a",

                      border:
                        "1px solid #1e293b",
                    }}
                  >

                    <Typography
                      sx={{
                        fontWeight:
                          750,

                        color:
                          "#f59e0b",
                      }}
                    >

                      Explicit Unknowns

                    </Typography>


                    <Typography
                      sx={{
                        mt:
                          1,

                        color:
                          "#cbd5e1",

                        lineHeight:
                          1.65,
                      }}
                    >

                      {
                        unknown.length
                      }

                      {" explicitly recorded unknown item(s)."}

                    </Typography>

                  </Box>

                </Box>


                <Alert
                  severity="warning"
                  sx={{
                    mt:
                      2,
                  }}
                >

                  Attack confirmation:
                  {" "}

                  <strong>

                    {
                      evidenceSummary
                        .attack_confirmed
                        ? "ESTABLISHED"
                        : "NOT ESTABLISHED"
                    }

                  </strong>

                  {" · "}

                  Causal relationship:
                  {" "}

                  <strong>

                    {
                      evidenceSummary
                        .causal_relationship_verified
                        ? "VERIFIED"
                        : "NOT VERIFIED"
                    }

                  </strong>

                  {" · "}

                  Confidence calibration:
                  {" "}

                  <strong>

                    {
                      investigation
                        .confidence_calibrated
                        ? "CALIBRATED"
                        : "NOT CALIBRATED"
                    }

                  </strong>

                </Alert>

              </CardContent>

            </Card>


            {/* ================================================= */}
            {/* FINDINGS / EVIDENCE */}
            {/* ================================================= */}

            <Box
              sx={{
                display:
                  "grid",

                gridTemplateColumns:
                  {

                    xs:
                      "1fr",

                    xl:
                      "1fr 1fr",
                  },

                gap:
                  2,

                mb:
                  3,
              }}
            >

              <Card>

                <CardContent
                  sx={{
                    p:
                      3,
                  }}
                >

                  <Stack

                    direction="row"

                    spacing={1}

                    alignItems="center"

                    sx={{
                      mb:
                        2,
                    }}

                  >

                    <SearchRounded
                      sx={{
                        color:
                          "#a78bfa",
                      }}
                    />


                    <Typography
                      variant="h6"
                    >

                      Investigation Findings

                    </Typography>

                  </Stack>


                  <FindingList
                    findings={
                      findings
                    }
                  />

                </CardContent>

              </Card>


              <Card>

                <CardContent
                  sx={{
                    p:
                      3,
                  }}
                >

                  <Stack

                    direction="row"

                    spacing={1}

                    alignItems="center"

                    sx={{
                      mb:
                        2,
                    }}

                  >

                    <TimelineRounded
                      sx={{
                        color:
                          "#60a5fa",
                      }}
                    />


                    <Typography
                      variant="h6"
                    >

                      Recorded Evidence

                    </Typography>

                  </Stack>


                  <Stack
                    spacing={1.2}
                  >

                    <Typography>

                      Incident events:
                      {" "}

                      <strong>

                        {
                          show(
                            observed
                              .timeline_event_count,
                            0,
                          )
                        }

                      </strong>

                    </Typography>


                    <Typography>

                      Evidence categories:
                      {" "}

                      <strong>

                        {
                          categories.length
                            ? categories.join(
                                " + ",
                              )
                            : "Not reported"
                        }

                      </strong>

                    </Typography>


                    <Typography>

                      Process entities:
                      {" "}

                      <strong>

                        {
                          show(
                            entitySummary
                              .process_count,
                            0,
                          )
                        }

                      </strong>

                    </Typography>


                    <Typography>

                      File entities:
                      {" "}

                      <strong>

                        {
                          show(
                            entitySummary
                              .file_count,
                            0,
                          )
                        }

                      </strong>

                    </Typography>


                    <Typography>

                      Network entities:
                      {" "}

                      <strong>

                        {
                          show(
                            entitySummary
                              .network_count,
                            0,
                          )
                        }

                      </strong>

                    </Typography>


                    <Typography>

                      Registry entities:
                      {" "}

                      <strong>

                        {
                          show(
                            entitySummary
                              .registry_count,
                            0,
                          )
                        }

                      </strong>

                    </Typography>


                    <Typography>

                      Production eligible:
                      {" "}

                      <strong>

                        {
                          validation
                            .production_eligible
                            ? "YES"
                            : "NO — validation evidence"
                        }

                      </strong>

                    </Typography>

                  </Stack>

                </CardContent>

              </Card>

            </Box>


            {/* ================================================= */}
            {/* TIMELINE */}
            {/* ================================================= */}

            <Card
              sx={{
                mb:
                  3,
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Typography
                  variant="h6"
                  sx={{
                    mb:
                      2,
                  }}
                >

                  Incident Timeline

                </Typography>


                {
                  timeline.length
                    ? (

                        timeline.map(
                          (
                            event,
                            index,
                          ) => (

                            <TimelineEntry

                              key={
                                event
                                  ?.event_id
                                ||
                                index
                              }

                              event={
                                event
                              }

                              index={
                                index
                              }

                            />
                          ),
                        )
                      )
                    : (

                        <Alert
                          severity="info"
                        >

                          No timeline events were returned.

                        </Alert>
                      )
                }

              </CardContent>

            </Card>


            {/* ================================================= */}
            {/* DETECTIONS */}
            {/* ================================================= */}

            <Card
              sx={{
                mb:
                  3,
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Typography
                  variant="h6"
                  sx={{
                    mb:
                      2,
                  }}
                >

                  Incident Detection Evidence

                </Typography>


                <Stack
                  spacing={1.2}
                >

                  {
                    detections.length
                      ? (

                          detections.map(
                            (
                              detection,
                              index,
                            ) => (

                              <DetectionCard

                                key={
                                  (
                                    detection
                                      ?.event_id
                                    ||
                                    index
                                  )
                                }

                                detection={
                                  detection
                                }

                              />
                            ),
                          )
                        )
                      : (

                          <Alert
                            severity="info"
                          >

                            No stored detection records were returned.

                          </Alert>
                        )
                  }

                </Stack>

              </CardContent>

            </Card>


            {/* ================================================= */}
            {/* RECOMMENDATIONS */}
            {/* ================================================= */}

            <Card
              sx={{
                mb:
                  3,
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Stack

                  direction="row"

                  spacing={1}

                  alignItems="center"

                >

                  <ShieldRounded
                    sx={{
                      color:
                        "#22c55e",
                    }}
                  />


                  <Typography
                    variant="h6"
                  >

                    Protection Recommendations

                  </Typography>

                </Stack>


                <Typography
                  sx={{
                    color:
                      "#94a3b8",

                    mt:
                      1,
                  }}
                >

                  These are advisory investigation outputs.
                  The Protection Simulator independently validates
                  candidate actions before displaying virtual plans.

                </Typography>


                <Divider
                  sx={{
                    my:
                      2,
                  }}
                />


                <Stack
                  spacing={1.2}
                >

                  {
                    recommendations.length
                      ? (

                          recommendations.map(
                            (
                              item,
                              index,
                            ) => (

                              <RecommendationCard

                                key={
                                  (
                                    item
                                      ?.action
                                    ||
                                    index
                                  )
                                }

                                item={
                                  item
                                }

                              />
                            ),
                          )
                        )
                      : (

                          <Alert
                            severity="info"
                          >

                            No advisory protection recommendations were generated.

                          </Alert>
                        )
                  }

                </Stack>

              </CardContent>

            </Card>


            {/* ================================================= */}
            {/* TECHNICAL DETAILS */}
            {/* ================================================= */}

            <Accordion
              sx={{
                mb:
                  3,
              }}
            >

              <AccordionSummary

                expandIcon={
                  <ExpandMoreRounded />
                }

              >

                <Typography
                  sx={{
                    fontWeight:
                      700,
                  }}
                >

                  Advanced Technical Investigation Details

                </Typography>

              </AccordionSummary>


              <AccordionDetails>

                <Alert
                  severity="info"
                  sx={{
                    mb:
                      2,
                  }}
                >

                  Individual agent decisions are technical supporting
                  outputs. Their confidence fields are not calibrated
                  probabilities and may use stricter evidence policies
                  than the validation-only canonical gate.

                </Alert>


                <Typography
                  sx={{
                    fontWeight:
                      700,

                    mb:
                      1,
                  }}
                >

                  Technical Agent Decisions

                </Typography>


                <Stack
                  spacing={1.2}
                >

                  {
                    agentDecisions.length
                      ? (

                          agentDecisions.map(
                            (
                              decision,
                              index,
                            ) => (

                              <AgentDecisionCard

                                key={
                                  (
                                    decision
                                      ?.agent
                                    ||
                                    index
                                  )
                                }

                                decision={
                                  decision
                                }

                              />
                            ),
                          )
                        )
                      : (

                          <Alert
                            severity="info"
                          >

                            No technical agent decisions were returned.

                          </Alert>
                        )
                  }

                </Stack>


                <Divider
                  sx={{
                    my:
                      3,
                  }}
                />


                <Typography
                  sx={{
                    fontWeight:
                      700,

                    mb:
                      1,
                  }}
                >

                  Contract / Safety

                </Typography>


                <Typography>

                  Schema:
                  {" "}

                  <strong>

                    {
                      show(
                        investigationData
                          .schema_version,
                      )
                    }

                  </strong>

                </Typography>


                <Typography
                  sx={{
                    mt:
                      0.8,
                  }}
                >

                  Pipeline:
                  {" "}

                  <strong>

                    {
                      show(
                        technical.pipeline,
                      )
                    }

                  </strong>

                </Typography>


                <Typography
                  sx={{
                    mt:
                      0.8,
                  }}
                >

                  Final decision:
                  {" "}

                  <strong>

                    {
                      friendlyDecision(
                        consensus
                          .final_decision
                        ||
                        investigation
                          .final_decision,
                      )
                    }

                  </strong>

                </Typography>


                <Typography
                  sx={{
                    mt:
                      0.8,
                  }}
                >

                  Read only:
                  {" "}

                  <strong>

                    {
                      safety.read_only
                        ? "YES"
                        : "NO"
                    }

                  </strong>

                </Typography>


                <Typography
                  sx={{
                    mt:
                      0.8,
                  }}
                >

                  Response authorized:
                  {" "}

                  <strong>

                    {
                      safety
                        .response_authorized
                        ? "YES"
                        : "NO"
                    }

                  </strong>

                </Typography>


                <Typography
                  sx={{
                    mt:
                      0.8,
                  }}
                >

                  Real response executed:
                  {" "}

                  <strong>

                    {
                      safety
                        .real_response_executed
                        ? "YES"
                        : "NO"
                    }

                  </strong>

                </Typography>


                {
                  reportSummary
                    .executive_summary
                  &&
                  (

                    <>

                      <Divider
                        sx={{
                          my:
                            3,
                        }}
                      />


                      <Typography
                        sx={{
                          fontWeight:
                            700,

                          mb:
                            1,
                        }}
                      >

                        Technical Report Summary

                      </Typography>


                      <Typography
                        sx={{
                          color:
                            "#94a3b8",

                          lineHeight:
                            1.7,
                        }}
                      >

                        {
                          userFacingText(
                            reportSummary
                              .executive_summary,
                          )
                        }

                      </Typography>

                    </>
                  )
                }

              </AccordionDetails>

            </Accordion>


            {/* ================================================= */}
            {/* NEXT STEP */}
            {/* ================================================= */}

            <Card
              sx={{
                background:
                  "linear-gradient(135deg,#11241b,#111827)",

                borderColor:
                  "rgba(34,197,94,0.3)",
              }}
            >

              <CardContent
                sx={{
                  p:
                    3,
                }}
              >

                <Stack

                  direction={{
                    xs:
                      "column",

                    md:
                      "row",
                  }}

                  justifyContent="space-between"

                  alignItems={{
                    xs:
                      "stretch",

                    md:
                      "center",
                  }}

                  spacing={2}

                >

                  <Box>

                    <Stack

                      direction="row"

                      spacing={1}

                      alignItems="center"

                    >

                      <WarningAmberRounded
                        sx={{
                          color:
                            "#f59e0b",
                        }}
                      />


                      <Typography
                        variant="h6"
                      >

                        Protection Review

                      </Typography>

                    </Stack>


                    <Typography
                      sx={{
                        color:
                          "#94a3b8",

                        mt:
                          1,
                      }}
                    >

                      Compare read-only virtual protection plans
                      using the same incident evidence.

                    </Typography>

                  </Box>


                  <Button

                    variant="contained"

                    startIcon={
                      <ScienceRounded />
                    }

                    endIcon={
                      <ArrowForwardRounded />
                    }

                    onClick={
                      () =>
                        navigate(
                          "/response-simulator",
                          {
                            state: {
                              incidentId,
                            },
                          },
                        )
                    }

                  >

                    Open Protection Simulator

                  </Button>

                </Stack>

              </CardContent>

            </Card>

          </>
        )
      }

    </Box>
  );
}