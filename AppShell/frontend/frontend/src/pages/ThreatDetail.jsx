import {
  useEffect,
  useMemo,
  useState,
} from "react";

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

import api from "../api/sentinelApi";


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


function array(
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


function numeric(
  value,
) {

  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {

    return null;
  }

  const parsed =
    Number(
      value,
    );

  return Number.isFinite(
    parsed,
  )
    ? parsed
    : null;
}


function key(
  value,
) {

  return String(
    value ?? "",
  )
    .trim()
    .toLowerCase();
}


function firstValue(
  ...values
) {

  for (
    const value
    of values
  ) {

    if (
      value !== null &&
      value !== undefined &&
      value !== ""
    ) {

      return value;
    }
  }

  return null;
}


// ================================================================
// FORMATTING
// ================================================================

function formatTime(
  value,
) {

  if (!value) {

    return "Not reported";
  }

  if (
    typeof value === "string" &&
    !/[zZ]$|[+-]\d\d:\d\d$/.test(
      value,
    )
  ) {

    return (
      `${value} `
      +
      "(timezone unspecified)"
    );
  }

  const date =
    new Date(
      value,
    );

  return Number.isNaN(
    date.getTime(),
  )
    ? String(value)
    : date.toLocaleString();
}


function formatConfidence(
  value,
) {

  const number =
    numeric(
      value,
    );

  if (
    number === null
  ) {

    return "Not reported";
  }

  const percentage =
    number <= 1
      ? number * 100
      : number;

  return (
    `${Math.round(
      percentage * 10,
    ) / 10}%`
  );
}


function humanize(
  value,
) {

  if (!value) {

    return "";
  }

  return String(
    value,
  )
    .replace(
      /_/g,
      " ",
    )
    .toLowerCase()
    .replace(
      /\b\w/g,
      (
        letter,
      ) =>
        letter.toUpperCase(),
    )
    .replace(
      /Powershell/g,
      "PowerShell",
    )
    .replace(
      /Rundll32/g,
      "rundll32",
    )
    .replace(
      /Regsvr32/g,
      "regsvr32",
    )
    .replace(
      /Wscript/g,
      "WScript",
    )
    .replace(
      /Cscript/g,
      "CScript",
    )
    .replace(
      /Mshta/g,
      "MSHTA",
    );
}


function productTitle(
  value,
) {

  return String(
    value ||
    "Security Detection",
  )
    .replace(
      /Powershell/g,
      "PowerShell",
    );
}


function readableList(
  value,
) {

  if (
    Array.isArray(
      value,
    )
  ) {

    const result =
      value
        .filter(Boolean)
        .map(
          (
            item,
          ) =>
            humanize(
              item,
            ),
        );

    return result.length
      ? result.join(
          " + ",
        )
      : "Not reported";
  }

  if (value) {

    return humanize(
      value,
    );
  }

  return "Not reported";
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


function verdictColor(
  verdict,
) {

  switch (
    String(
      verdict || "",
    ).toUpperCase()
  ) {

    case "CONFIRMED_THREAT":

      return "error";

    case "LIKELY_THREAT":

    case "SUSPICIOUS":

      return "warning";

    case "SAFE":

    case "BENIGN":

      return "success";

    default:

      return "default";
  }
}


function stateColor(
  state,
) {

  switch (
    String(
      state || "",
    ).toUpperCase()
  ) {

    case "PROTECTED":

    case "QUARANTINED":

    case "RESOLVED":

    case "VERIFIED_SAFE":

      return "success";

    case "PROTECTION_RECOMMENDED":

    case "USER_ACTION_REQUIRED":

    case "NEEDS_ATTENTION":

    case "SUSPICIOUS":

      return "warning";

    case "PROTECTION_FAILED":

      return "error";

    default:

      return "default";
  }
}


// ================================================================
// CANONICAL EVIDENCE
// ================================================================

function observedEvidence(
  threat,
) {

  return array(
    object(
      threat?.evidence,
    ).observed,
  );
}


function evidenceOfType(
  threat,
  type,
) {

  const target =
    String(
      type || "",
    ).toUpperCase();

  const result =
    observedEvidence(
      threat,
    ).find(
      (
        item,
      ) =>
        String(
          item?.type || "",
        ).toUpperCase() ===
        target,
    );

  return object(
    result?.data,
  );
}


function evidenceBoundaries(
  threat,
) {

  const evidence =
    object(
      threat?.evidence,
    );

  return {

    observed:
      array(
        evidence.observed,
      ),

    inferred:
      array(
        evidence.inferred,
      ),

    unknown:
      array(
        evidence.unknown,
      ),
  };
}


// ================================================================
// DETECTION REASONS
// ================================================================

function detectionReasons(
  threat,
) {

  const value =
    object(
      threat?.source_reference,
    ).detection_reason;


  if (
    Array.isArray(
      value,
    )
  ) {

    return value
      .filter(Boolean)
      .map(
        (
          item,
        ) =>
          typeof item ===
            "string"
            ? item.replace(
                /_/g,
                " ",
              )
            : JSON.stringify(
                item,
              ),
      );
  }


  if (
    typeof value ===
      "string"
  ) {

    try {

      const parsed =
        JSON.parse(
          value,
        );

      if (
        Array.isArray(
          parsed,
        )
      ) {

        return parsed
          .filter(Boolean)
          .map(
            (
              item,
            ) =>
              String(
                item,
              ).replace(
                /_/g,
                " ",
              ),
          );
      }

    } catch {

      // Plain stored string.
    }

    return value
      ? [
          value.replace(
            /_/g,
            " ",
          ),
        ]
      : [];
  }


  return [];
}


// ================================================================
// INCIDENT
// ================================================================

function relatedIncidentIds(
  threat,
) {

  const incident =
    object(
      threat?.incident,
    );

  const ids =
    array(
      incident
        .related_incident_ids,
    )
      .filter(Boolean)
      .map(String);


  if (
    ids.length
  ) {

    return [
      ...new Set(
        ids,
      ),
    ];
  }


  if (
    threat?.incident_id
  ) {

    return [
      String(
        threat.incident_id,
      ),
    ];
  }


  return [];
}


async function getIncidentById(
  incidentId,
) {

  if (
    !incidentId
  ) {

    return null;
  }

  const response =
    await api.get(
      `/detected-incidents/${encodeURIComponent(
        incidentId,
      )}`,
    );

  return (
    response.data ||
    null
  );
}


// ================================================================
// TIMELINE CATEGORY
// ================================================================

function inferTimelineCategory(
  event,
) {

  const explicit =
    String(
      event?.event_category ||
      event?.category ||
      "",
    ).toUpperCase();


  if (
    explicit ===
    "SECURITY"
  ) {

    const eventType =
      String(
        event?.event_type ||
        "",
      ).toLowerCase();

    return eventType.includes(
      "auth",
    )
      ? "AUTHENTICATION"
      : "SYSTEM";
  }


  if (explicit) {

    return explicit;
  }


  const eventType =
    String(
      event?.event_type ||
      "",
    ).toLowerCase();


  if (
    eventType.startsWith(
      "process",
    )
  ) {

    return "PROCESS";
  }


  if (
    eventType.startsWith(
      "file",
    )
  ) {

    return "FILE";
  }


  if (
    eventType.startsWith(
      "network",
    )
  ) {

    return "NETWORK";
  }


  if (
    eventType.startsWith(
      "registry",
    )
  ) {

    return "REGISTRY";
  }


  if (
    eventType.startsWith(
      "startup",
    )
  ) {

    return "STARTUP";
  }


  if (
    eventType.startsWith(
      "security_auth",
    )
  ) {

    return "AUTHENTICATION";
  }


  if (
    eventType.startsWith(
      "security",
    )
  ) {

    return "SYSTEM";
  }


  return "OTHER";
}


// ================================================================
// CURRENT EVENT
// ================================================================

function findCurrentEvent(
  incident,
  eventId,
) {

  const timeline =
    array(
      incident?.timeline,
    );

  return (
    timeline.find(
      (
        item,
      ) =>
        key(
          item?.event_id,
        )
        ===
        key(
          eventId,
        ),
    )
    ||
    null
  );
}


// ================================================================
// PROCESS FUSION CONTRACT
// ================================================================

function isFusionThreat(
  threat,
) {

  return (
    String(
      threat
        ?.model_evidence
        ?.type ||
      "",
    ).toUpperCase() ===
      "PROCESS_FUSION_V3"
  );
}


function buildProcessContract(
  threat,
  currentEvent,
) {

  const model =
    object(
      threat?.model_evidence,
    );

  const process =
    evidenceOfType(
      threat,
      "PROCESS",
    );

  const eventProcess =
    object(
      currentEvent?.process,
    );

  const rules =
    object(
      model.rules,
    );

  const fusion =
    object(
      model.fusion,
    );

  const consensus =
    object(
      model.consensus,
    );


  return {

    ...eventProcess,

    ...process,

    isolation_forest:
      object(
        model.isolation_forest,
      ),

    autoencoder:
      object(
        model.autoencoder,
      ),

    temporal_ai:
      object(
        model.temporal_ai,
      ),

    fusion_version:
      fusion.version ??
      process.fusion_version ??
      null,

    fusion_score:
      fusion.score ??
      process.fusion_score ??
      null,

    fusion_severity:
      fusion.severity ??
      process.fusion_severity ??
      null,

    fusion_confidence:
      fusion.confidence ??
      process.fusion_confidence ??
      null,

    fusion_reasons:
      array(
        fusion.reasons ??
        process.fusion_reasons,
      ),

    rule_score:
      rules.score ??
      process.rule_score ??
      null,

    behavior_reasons:
      array(
        rules.reasons ??
        process.behavior_reasons,
      ),

    ai_consensus_score:
      consensus.score ??
      process.ai_consensus_score ??
      null,

    ai_consensus:
      consensus.label ??
      process.ai_consensus ??
      null,

    ai_behavior_context:
      object(
        consensus.context ??
        process.ai_behavior_context,
      ),
  };
}


function buildModelScores(
  threat,
  process,
) {

  const model =
    object(
      threat?.model_evidence,
    );

  const rules =
    object(
      model.rules,
    );

  const fusion =
    object(
      model.fusion,
    );

  const consensus =
    object(
      model.consensus,
    );

  const forest =
    object(
      model.isolation_forest,
    );

  const encoder =
    object(
      model.autoencoder,
    );

  const temporal =
    object(
      model.temporal_ai,
    );


  return {

    rule_score:
      rules.score ??
      process.rule_score ??
      null,

    isolation_forest_score:
      forest.anomaly_confidence ??
      null,

    autoencoder_score:
      encoder.anomaly_confidence ??
      null,

    temporal_score:
      temporal.score ??
      temporal.temporal_score ??
      null,

    fusion_score:
      fusion.score ??
      process.fusion_score ??
      null,

    evidence_confidence:
      fusion.confidence ??
      process.fusion_confidence ??
      null,

    ai_consensus_score:
      consensus.score ??
      process.ai_consensus_score ??
      null,

    ai_agreement:
      consensus.context
        ?.agreement ??
      process
        .ai_behavior_context
        ?.agreement ??
      null,

    ai_disagreement:
      consensus.context
        ?.disagreement ??
      process
        .ai_behavior_context
        ?.disagreement ??
      null,
  };
}


// ================================================================
// EVIDENCE ROWS
// ================================================================

function buildEvidenceRows({
  threat,
  currentEvent,
}) {

  const category =
    String(
      threat?.category ||
      "OTHER",
    ).toUpperCase();


  const process = {

    ...object(
      currentEvent?.process,
    ),

    ...evidenceOfType(
      threat,
      "PROCESS",
    ),
  };


  const file = {

    ...object(
      currentEvent?.file,
    ),

    ...evidenceOfType(
      threat,
      "FILE",
    ),
  };


  const network = {

    ...object(
      currentEvent?.network,
    ),

    ...evidenceOfType(
      threat,
      "NETWORK",
    ),
  };


  const registry = {

    ...object(
      currentEvent?.registry,
    ),

    ...evidenceOfType(
      threat,
      "REGISTRY",
    ),
  };


  const authentication = {

    ...evidenceOfType(
      threat,
      "AUTHENTICATION",
    ),
  };


  const system = {

    ...evidenceOfType(
      threat,
      "SYSTEM",
    ),
  };


  const startup = {

    ...evidenceOfType(
      threat,
      "STARTUP",
    ),
  };


  const metadata = {

    ...object(
      currentEvent?.metadata,
    ),
  };


  if (
    category ===
    "PROCESS"
  ) {

    return [

      {
        label:
          "Process",

        value:
          firstValue(
            process.process_name,
            process.name,
          ),
      },

      {
        label:
          "PID",

        value:
          process.pid,
      },

      {
        label:
          "Parent process",

        value:
          firstValue(
            process.parent_process_name,
            process.parent_name,
          ),
      },

      {
        label:
          "Command line",

        value:
          firstValue(
            process.command_line,
            process.cmdline,
          ),
      },
    ];
  }


  if (
    category ===
    "FILE"
  ) {

    return [

      {
        label:
          "File name",

        value:
          firstValue(
            file.name,
            file.file_name,
            file.filename,
          ),
      },

      {
        label:
          "File path",

        value:
          firstValue(
            file.path,
            file.file_path,
          ),
      },

      {
        label:
          "SHA-256",

        value:
          firstValue(
            file.sha256,
            file.hash_sha256,
            file.file_hash,
          ),
      },

      {
        label:
          "File operation",

        value:
          firstValue(
            file.operation,
            file.action,
            threat.event_type,
          ),
      },
    ];
  }


  if (
    category ===
    "NETWORK"
  ) {

    const remoteIp =
      firstValue(
        network.remote_ip,
        network.destination_ip,
        network.dest_ip,
        network.target_ip,
      );

    const remotePort =
      firstValue(
        network.remote_port,
        network.destination_port,
        network.dest_port,
      );


    return [

      {
        label:
          "Remote endpoint",

        value:
          remoteIp &&
          remotePort
            ? `${remoteIp}:${remotePort}`
            : remoteIp,
      },

      {
        label:
          "Protocol",

        value:
          network.protocol,
      },

      {
        label:
          "Bytes sent",

        value:
          firstValue(
            network.bytes_sent,
            network.outbound_bytes,
          ),
      },

      {
        label:
          "Network pattern",

        value:
          firstValue(
            network.scanned_port_count !==
              null &&
            network.scanned_port_count !==
              undefined
              ? (
                  `${network.scanned_port_count} `
                  +
                  "destination ports scanned"
                )
              : null,

            network.connection_rate !==
              null &&
            network.connection_rate !==
              undefined
              ? (
                  `${network.connection_rate} `
                  +
                  "connections / interval"
                )
              : null,

            network.unique_remote_count !==
              null &&
            network.unique_remote_count !==
              undefined
              ? (
                  `${network.unique_remote_count} `
                  +
                  "remote hosts"
                )
              : null,

            threat.event_type,
          ),
      },
    ];
  }


  if (
    category ===
    "REGISTRY"
  ) {

    return [

      {
        label:
          "Registry key",

        value:
          firstValue(
            registry.key,
            registry.registry_key,
            registry.path,
          ),
      },

      {
        label:
          "Value name",

        value:
          firstValue(
            registry.value_name,
            registry.name,
          ),
      },

      {
        label:
          "Value data",

        value:
          firstValue(
            registry.value_data,
            registry.data,
          ),
      },

      {
        label:
          "Registry operation",

        value:
          firstValue(
            registry.operation,
            registry.action,
            threat.event_type,
          ),
      },
    ];
  }


  if (
    category ===
    "AUTHENTICATION"
  ) {

    return [

      {
        label:
          "Source address",

        value:
          firstValue(
            network.source_ip,
            network.remote_ip,
            authentication.source_ip,
            authentication.remote_ip,
            metadata.source_ip,
            metadata.remote_ip,
          ),
      },

      {
        label:
          "Account",

        value:
          firstValue(
            authentication.username,
            authentication.user,
            authentication.account,
            metadata.username,
            metadata.user,
            metadata.account,
          ),
      },

      {
        label:
          "Authentication event",

        value:
          humanize(
            threat.event_type,
          ),
      },

      {
        label:
          "Failure count",

        value:
          firstValue(
            authentication.failure_count,
            authentication.failed_attempts,
            metadata.failure_count,
            metadata.failed_attempts,
          ),
      },
    ];
  }


  if (
    category ===
    "STARTUP"
  ) {

    return [

      {
        label:
          "Startup entry",

        value:
          firstValue(
            startup.entry_name,
            startup.name,
            startup.startup_name,
          ),
      },

      {
        label:
          "Startup path",

        value:
          firstValue(
            startup.path,
            startup.target,
            startup.command,
          ),
      },

      {
        label:
          "Trusted",

        value:
          startup.trusted ===
            undefined
            ? null
            : String(
                startup.trusted,
              ),
      },

      {
        label:
          "Event type",

        value:
          humanize(
            threat.event_type,
          ),
      },
    ];
  }


  if (
    category ===
    "SYSTEM"
  ) {

    return [

      {
        label:
          "System event",

        value:
          humanize(
            threat.event_type,
          ),
      },

      {
        label:
          "Account / subject",

        value:
          firstValue(
            system.account,
            system.username,
            system.user,
            system.subject,
          ),
      },

      {
        label:
          "Privilege",

        value:
          firstValue(
            system.privilege,
            system.new_privilege,
            system.role,
          ),
      },

      {
        label:
          "Unexpected",

        value:
          system.unexpected ===
            undefined
            ? null
            : String(
                system.unexpected,
              ),
      },
    ];
  }


  return [

    {
      label:
        "Event type",

      value:
        humanize(
          threat.event_type,
        ),
    },

    {
      label:
        "Detector",

      value:
        threat.engine,
    },
  ];
}


// ================================================================
// RISK DESCRIPTION
// ================================================================

function riskDescription(
  threat,
) {

  const semantics =
    threat
      ?.risk
      ?.detection
      ?.semantics;


  if (
    semantics ===
    "DETECTOR_RISK_SCORE_NOT_PROBABILITY"
  ) {

    if (
      isFusionThreat(
        threat,
      )
    ) {

      return (
        "Fusion-v3 detector risk score produced from "
        +
        "the recorded process evidence. It is not a "
        +
        "calibrated probability of malicious activity."
      );
    }


    return (
      "Recorded detector risk score. It is not a "
      +
      "calibrated probability that an attack occurred."
    );
  }


  return (
    "Recorded security-detector risk score."
  );
}


// ================================================================
// CORROBORATION
// ================================================================

function normalizeIncidentCategory(
  category,
  threatCategory,
) {

  const value =
    String(
      category ||
      "",
    ).toUpperCase();


  if (
    value ===
    "SECURITY"
  ) {

    return (
      String(
        threatCategory ||
        "",
      ).toUpperCase() ===
      "AUTHENTICATION"
    )
      ? "AUTHENTICATION"
      : "SYSTEM";
  }


  return value;
}


function buildCorroboration(
  threat,
  incident,
) {

  if (
    !incident
  ) {

    return {

      title:
        "Standalone detection",

      detail:
        (
          "No correlated incident has been "
          +
          "recorded for this detection."
        ),

      categories:
        [],
    };
  }


  const categories =
    new Set();


  for (
    const category
    of array(
      incident.categories,
    )
  ) {

    if (category) {

      categories.add(
        normalizeIncidentCategory(
          category,
          threat?.category,
        ),
      );
    }
  }


  for (
    const event
    of array(
      incident.timeline,
    )
  ) {

    const category =
      inferTimelineCategory(
        event,
      );

    if (
      category &&
      category !==
      "OTHER"
    ) {

      categories.add(
        category,
      );
    }
  }


  const list =
    [
      ...categories,
    ];


  const eventCount =
    Number(
      incident.event_count ||
      incident.event_ids
        ?.length ||
      incident.timeline
        ?.length ||
      0,
    );


  if (
    list.length > 1
  ) {

    return {

      title:
        `${list.length} correlated evidence categories`,

      detail:
        list.join(
          " + ",
        ),

      categories:
        list,
    };
  }


  if (
    eventCount > 1
  ) {

    return {

      title:
        `${eventCount} correlated events`,

      detail:
        list.length
          ? list.join(
              " + ",
            )
          : "Multiple recorded events",

      categories:
        list,
    };
  }


  return {

    title:
      "Single-event incident",

    detail:
      list.length
        ? list[0]
        : "One recorded event",

    categories:
      list,
  };
}


// ================================================================
// EXPLANATION
// ================================================================

function buildExplanation(
  threat,
  process,
  scores,
) {

  const statements = [];

  const reasons =
    detectionReasons(
      threat,
    );


  if (
    reasons.length
  ) {

    statements.push(
      ...reasons.slice(
        0,
        4,
      ),
    );
  }


  if (
    isFusionThreat(
      threat,
    )
  ) {

    const temporal =
      object(
        threat
          ?.model_evidence
          ?.temporal_ai,
      );


    const ruleScore =
      numeric(
        scores.rule_score,
      );


    const temporalScore =
      numeric(
        scores.temporal_score,
      );


    const fusionScore =
      numeric(
        scores.fusion_score,
      );


    if (
      ruleScore !==
      null
    ) {

      statements.push(
        (
          "Behavioral rule evidence scored "
          +
          `${ruleScore}/100.`
        ),
      );
    }


    if (
      temporalScore !==
      null
    ) {

      statements.push(
        (
          `Temporal AI scored ${temporalScore}/100`
          +
          (
            temporal.label
              ? (
                  ` (${humanize(
                    temporal.label,
                  )})`
                )
              : ""
          )
          +
          "."
        ),
      );
    }


    if (
      fusionScore !==
      null
    ) {

      statements.push(
        (
          "Fusion-v3 combined the available "
          +
          `evidence into a ${fusionScore}/100 `
          +
          `${process.fusion_severity || threat.severity || ""} `
          +
          "result."
        ),
      );
    }


    if (
      scores.ai_agreement
    ) {

      statements.push(
        (
          "Supporting signals: "
          +
          `${readableList(
            scores.ai_agreement,
          )}.`
        ),
      );
    }


    if (
      scores.ai_disagreement
    ) {

      statements.push(
        (
          "Signals that did not independently agree: "
          +
          `${readableList(
            scores.ai_disagreement,
          )}.`
        ),
      );
    }
  }


  if (
    !statements.length
  ) {

    statements.push(
      (
        `The ${show(
          threat?.engine,
          "detector",
        )} recorded this event as `
        +
        `${humanize(
          threat?.threat_type ||
          "a security detection",
        )}.`
      ),
    );
  }


  return [
    ...new Set(
      statements,
    ),
  ];
}


// ================================================================
// SMALL COMPONENTS
// ================================================================

function DetailField({
  label,
  value,
}) {

  return (

    <Box
      sx={{
        py:
          1.1,
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
          mt:
            0.35,

          fontSize:
            13,

          overflowWrap:
            "anywhere",
        }}
      >

        {
          show(
            value,
          )
        }

      </Typography>


      <Divider
        sx={{
          mt:
            1.1,
        }}
      />

    </Box>
  );
}


function EvidenceGrid({
  rows,
}) {

  const visible =
    rows.filter(
      (
        row,
      ) =>
        row.value !==
          null &&
        row.value !==
          undefined &&
        row.value !==
          "",
    );


  if (
    !visible.length
  ) {

    return (

      <Alert
        severity="info"
      >

        No additional category-specific evidence was
        stored for this event.

      </Alert>
    );
  }


  return (

    <Box
      sx={{
        display:
          "grid",

        gridTemplateColumns:
          {

            xs:
              "1fr",

            md:
              "repeat(2,minmax(0,1fr))",
          },

        gap:
          1.5,
      }}
    >

      {
        visible.map(
          (
            row,
          ) => (

            <Box

              key={
                row.label
              }

              sx={{
                p:
                  1.6,

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

                {row.label}

              </Typography>


              <Typography
                sx={{
                  mt:
                    0.5,

                  fontSize:
                    13,

                  fontWeight:
                    650,

                  overflowWrap:
                    "anywhere",
                }}
              >

                {
                  show(
                    row.value,
                  )
                }

              </Typography>

            </Box>
          ),
        )
      }

    </Box>
  );
}


// ================================================================
// MODEL CARD
// ================================================================

function ModelCard({
  title,
  model,
  modelType,
}) {

  if (
    model?.available !==
    true
  ) {

    return null;
  }


  const reportedScore =
    numeric(
      model.anomaly_confidence,
    );


  return (

    <Card
      variant="outlined"
      sx={{
        borderColor:
          "rgba(139,92,246,0.35)",
      }}
    >

      <CardContent
        sx={{
          p:
            2.5,
        }}
      >

        <Stack

          direction="row"

          justifyContent="space-between"

          alignItems="flex-start"

          spacing={1}

        >

          <Typography
            sx={{
              fontWeight:
                700,
            }}
          >

            {title}

          </Typography>


          <Chip

            size="small"

            label={
              show(
                model.anomaly_label,
                "Result recorded",
              )
            }

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
              1.5,
          }}
        >

          Reported anomaly measure

        </Typography>


        <Typography
          sx={{
            fontSize:
              24,

            fontWeight:
              750,
          }}
        >

          {
            reportedScore ===
              null
              ? "Not reported"
              : reportedScore
          }

        </Typography>


        {
          reportedScore !==
            null
          &&
          (

            <LinearProgress

              variant="determinate"

              value={
                Math.max(
                  0,
                  Math.min(
                    100,
                    reportedScore,
                  ),
                )
              }

              sx={{
                mt:
                  1,

                height:
                  7,

                borderRadius:
                  2,

                background:
                  "#1e293b",
              }}

            />
          )
        }


        <Typography
          sx={{
            color:
              "#64748b",

            fontSize:
              11,

            mt:
              1,
          }}
        >

          This is a model-specific anomaly measure,
          not a calibrated malware probability.

        </Typography>


        <DetailField
          label="Model version"
          value={
            model.model_version
          }
        />


        {
          modelType ===
            "forest"
            ? (

                <>

                  <DetailField

                    label="Model outlier"

                    value={
                      model.model_outlier ===
                        undefined
                        ? null
                        : String(
                            model.model_outlier,
                          )
                    }

                  />


                  <DetailField

                    label="Decision score"

                    value={
                      model.decision_score
                    }

                  />

                </>
              )
            : (

                <>

                  <DetailField

                    label="Reconstruction error"

                    value={
                      model.reconstruction_error
                    }

                  />


                  <DetailField

                    label="Reconstruction region"

                    value={
                      model.reconstruction_region
                    }

                  />

                </>
              )
        }

      </CardContent>

    </Card>
  );
}


// ================================================================
// TEMPORAL AI
// ================================================================

function TemporalCard({
  temporal,
}) {

  if (
    temporal?.available !==
    true
  ) {

    return null;
  }


  const score =
    numeric(
      temporal.score ??
      temporal.temporal_score,
    );


  return (

    <Card
      variant="outlined"
      sx={{
        borderColor:
          "rgba(96,165,250,0.35)",
      }}
    >

      <CardContent
        sx={{
          p:
            2.5,
        }}
      >

        <Typography
          sx={{
            fontWeight:
              700,
          }}
        >

          Temporal AI

        </Typography>


        <Typography
          sx={{
            fontSize:
              24,

            fontWeight:
              750,

            mt:
              1,
          }}
        >

          {
            score === null
              ? show(
                  temporal.label,
                  "Result recorded",
                )
              : `${score}/100`
          }

        </Typography>


        <DetailField
          label="Temporal label"
          value={
            temporal.label
          }
        />


        <DetailField
          label="Severity"
          value={
            temporal.severity
          }
        />


        <DetailField
          label="Reason"
          value={
            temporal.reason
          }
        />

      </CardContent>

    </Card>
  );
}


// ================================================================
// FEATURE EVIDENCE
// ================================================================

function FeatureEvidence({
  forest,
  encoder,
}) {

  const deviations =
    array(
      forest
        ?.feature_deviations,
    );

  const reconstruction =
    array(
      encoder
        ?.feature_reconstruction_errors,
    );


  if (
    !deviations.length &&
    !reconstruction.length
  ) {

    return null;
  }


  return (

    <Stack
      spacing={2}
    >

      {
        deviations.length > 0
        &&
        (

          <Box>

            <Typography
              sx={{
                fontWeight:
                  700,

                mb:
                  1,
              }}
            >

              Isolation Forest feature deviations

            </Typography>


            <Typography
              sx={{
                color:
                  "#94a3b8",

                fontSize:
                  12,

                mb:
                  1.5,
              }}
            >

              These values describe deviation from the
              model reference distribution; they are not
              malicious actions by themselves.

            </Typography>


            {
              deviations
                .slice(
                  0,
                  5,
                )
                .map(
                  (
                    item,
                    index,
                  ) => (

                    <Box

                      key={
                        `${item.feature}-${index}`
                      }

                      sx={{
                        p:
                          1.5,

                        mb:
                          1,

                        background:
                          "#0f172a",

                        borderRadius:
                          2,
                      }}

                    >

                      <Typography
                        sx={{
                          fontWeight:
                            650,
                        }}
                      >

                        {
                          humanize(
                            item.feature,
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

                        Observed:
                        {" "}
                        {
                          show(
                            item.value,
                          )
                        }

                        {" · "}

                        Reference mean:
                        {" "}
                        {
                          show(
                            item.baseline_mean,
                          )
                        }

                        {" · "}

                        Deviation:
                        {" "}
                        {
                          show(
                            item.deviation_std,
                          )
                        }
                        {" "}
                        SD

                      </Typography>

                    </Box>
                  ),
                )
            }

          </Box>
        )
      }


      {
        reconstruction.length > 0
        &&
        (

          <Box>

            <Typography
              sx={{
                fontWeight:
                  700,

                mb:
                  1,
              }}
            >

              Autoencoder reconstruction differences

            </Typography>


            {
              reconstruction
                .slice(
                  0,
                  5,
                )
                .map(
                  (
                    item,
                    index,
                  ) => (

                    <Box

                      key={
                        `${item.feature}-${index}`
                      }

                      sx={{
                        p:
                          1.5,

                        mb:
                          1,

                        background:
                          "#0f172a",

                        borderRadius:
                          2,
                      }}

                    >

                      <Typography
                        sx={{
                          fontWeight:
                            650,
                        }}
                      >

                        {
                          humanize(
                            item.feature,
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

                        Actual:
                        {" "}
                        {
                          show(
                            item.actual_value,
                          )
                        }

                        {" · "}

                        Reconstructed:
                        {" "}
                        {
                          show(
                            item.reconstructed_value,
                          )
                        }

                      </Typography>

                    </Box>
                  ),
                )
            }

          </Box>
        )
      }

    </Stack>
  );
}


// ================================================================
// TIMELINE ENTRY
// ================================================================

function TimelineEntry({
  item,
}) {

  const event =
    item &&
    typeof item ===
      "object"
      ? item
      : {
          description:
            String(
              item,
            ),
        };


  const category =
    inferTimelineCategory(
      event,
    );


  const title =
    humanize(
      event.event_type ||
      event.title ||
      event.type ||
      "Recorded event",
    );


  const description =
    event.description ||
    event.detection
      ?.threat_type ||
    event.message ||
    event.reason ||
    event.event_id ||
    (
      "No additional event description "
      +
      "was recorded."
    );


  return (

    <Box
      sx={{
        display:
          "flex",

        gap:
          2,

        pb:
          2,

        mb:
          1,

        borderBottom:
          "1px solid #1e293b",
      }}
    >

      <TimelineRounded
        sx={{
          color:
            "#60a5fa",

          mt:
            0.3,
        }}
      />


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

          alignItems="center"

          flexWrap="wrap"

          useFlexGap

        >

          <Typography
            sx={{
              fontWeight:
                650,
            }}
          >

            {title}

          </Typography>


          <Chip

            size="small"

            label={
              category
            }

            variant="outlined"

          />

        </Stack>


        <Typography
          sx={{
            fontSize:
              12,

            color:
              "#94a3b8",

            mt:
              0.5,

            overflowWrap:
              "anywhere",
          }}
        >

          {
            humanize(
              description,
            )
          }

        </Typography>


        <Typography
          sx={{
            fontSize:
              11,

            color:
              "#64748b",

            mt:
              0.5,
          }}
        >

          {
            formatTime(
              event.timestamp ||
              event.time,
            )
          }

        </Typography>

      </Box>

    </Box>
  );
}


// ================================================================
// PAGE
// ================================================================

export default function ThreatDetail() {

  const navigate =
    useNavigate();

  const location =
    useLocation();

  const {
    threatId,
  } =
    useParams();


  const rawId =
    decodeURIComponent(
      String(
        threatId ||
        "",
      ),
    );


  const requestedId =
    /^\d+$/.test(
      rawId,
    )
      ? `detection-${rawId}`
      : rawId;


  const stateThreat =
    location.state
      ?.canonicalThreat;


  const validStateThreat =
    stateThreat?.id ===
      requestedId
      ? stateThreat
      : null;


  const [
    threat,
    setThreat,
  ] =
    useState(
      validStateThreat,
    );


  const [
    primaryIncident,
    setPrimaryIncident,
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


  const [
    incidentError,
    setIncidentError,
  ] =
    useState(
      "",
    );


  // ==============================================================
  // LOAD CANONICAL THREAT + HYDRATED PRIMARY INCIDENT
  // ==============================================================

  useEffect(
    () => {

      let active =
        true;


      async function load() {

        setLoading(
          true,
        );

        setError(
          "",
        );

        setIncidentError(
          "",
        );


        let resolvedThreat =
          validStateThreat;


        try {

          const response =
            await api.get(
              `/security/threats/${encodeURIComponent(
                requestedId,
              )}`,
            );


          if (
            !active
          ) {

            return;
          }


          resolvedThreat =
            response.data ||
            resolvedThreat;


          if (
            resolvedThreat
              ?.schema_version !==
            CONTRACT_VERSION
          ) {

            throw new Error(
              (
                "Unexpected canonical security "
                +
                "contract version."
              ),
            );
          }


          setThreat(
            resolvedThreat,
          );

        } catch (
          threatLoadError
        ) {

          if (
            !active
          ) {

            return;
          }


          if (
            !resolvedThreat
          ) {

            setThreat(
              null,
            );
          }


          setError(
            threatLoadError
              ?.response
              ?.data
              ?.detail
            ||
            threatLoadError
              ?.message
            ||
            (
              "Unable to retrieve canonical "
              +
              "threat details."
            ),
          );
        }


        const incidentId =
          resolvedThreat
            ?.incident
            ?.incident_id
          ||
          resolvedThreat
            ?.incident_id
          ||
          null;


        if (
          incidentId
        ) {

          try {

            const hydrated =
              await getIncidentById(
                incidentId,
              );


            if (
              active
            ) {

              setPrimaryIncident(
                hydrated ||
                object(
                  resolvedThreat
                    ?.incident,
                ),
              );
            }

          } catch (
            incidentLoadError
          ) {

            if (
              active
            ) {

              setPrimaryIncident(
                object(
                  resolvedThreat
                    ?.incident,
                ),
              );


              setIncidentError(
                incidentLoadError
                  ?.response
                  ?.data
                  ?.detail
                ||
                incidentLoadError
                  ?.message
                ||
                (
                  "The primary incident "
                  +
                  "timeline could not be loaded."
                ),
              );
            }
          }

        } else {

          setPrimaryIncident(
            null,
          );
        }


        if (
          active
        ) {

          setLoading(
            false,
          );
        }
      }


      load();


      return (
        () => {

          active =
            false;
        }
      );

    },

    [
      requestedId,
    ],
  );


  // ==============================================================
  // LOADING / NOT FOUND
  // ==============================================================

  if (
    loading &&
    !threat
  ) {

    return (

      <Box
        sx={{
          textAlign:
            "center",

          py:
            5,
        }}
      >

        <CircularProgress />


        <Typography
          sx={{
            mt:
              2,
          }}
        >

          Loading canonical threat evidence...

        </Typography>

      </Box>
    );
  }


  if (
    !threat
  ) {

    return (

      <Box>

        <Button

          startIcon={
            <ArrowBackRounded />
          }

          onClick={
            () =>
              navigate(
                "/threats",
              )
          }

          sx={{
            mb:
              2,
          }}

        >

          Back to Threats

        </Button>


        <Alert
          severity="warning"
        >

          {
            error ||
            (
              `Security threat ${requestedId} `
              +
              "was not found."
            )
          }

        </Alert>

      </Box>
    );
  }


  // ==============================================================
  // CANONICAL CURRENT THREAT
  // ==============================================================

  const category =
    String(
      threat.category ||
      "OTHER",
    ).toUpperCase();


  const severity =
    String(
      threat.severity ||
      "UNKNOWN",
    ).toUpperCase();


  const color =
    severityColor(
      severity,
    );


  const currentEvent =
    findCurrentEvent(
      primaryIncident,
      threat.event_id,
    );


  const process =
    buildProcessContract(
      threat,
      currentEvent,
    );


  const scores =
    buildModelScores(
      threat,
      process,
    );


  const forest =
    object(
      threat
        ?.model_evidence
        ?.isolation_forest,
    );


  const encoder =
    object(
      threat
        ?.model_evidence
        ?.autoencoder,
    );


  const temporal =
    object(
      threat
        ?.model_evidence
        ?.temporal_ai,
    );


  const fusion =
    isFusionThreat(
      threat,
    );


  const risk =
    numeric(
      threat
        ?.risk
        ?.detection
        ?.score,
    );


  const confidence =
    threat.confidence;


  const reasons =
    detectionReasons(
      threat,
    );


  const evidenceRows =
    buildEvidenceRows({
      threat,
      currentEvent,
    });


  const canonicalIncident =
    object(
      threat.incident,
    );


  const effectiveIncident =
    primaryIncident ||
    (
      canonicalIncident
        .incident_id
        ? canonicalIncident
        : null
    );


  const corroboration =
    buildCorroboration(
      threat,
      effectiveIncident,
    );


  const timeline =
    array(
      primaryIncident
        ?.timeline,
    );


  const explanations =
    buildExplanation(
      threat,
      process,
      scores,
    );


  const incidentId =
    canonicalIncident
      .incident_id
    ||
    threat.incident_id
    ||
    null;


  const relatedIds =
    relatedIncidentIds(
      threat,
    );


  const incidentLinked =
    Boolean(
      incidentId,
    );


  const boundaries =
    evidenceBoundaries(
      threat,
    );


  const hasProcessModels =
    fusion &&
    (
      forest.available ===
        true
      ||
      encoder.available ===
        true
      ||
      temporal.available ===
        true
    );


  const hasFeatureEvidence =
    (
      array(
        forest
          .feature_deviations,
      ).length > 0
    )
    ||
    (
      array(
        encoder
          .feature_reconstruction_errors,
      ).length > 0
    );


  // ==============================================================
  // RENDER
  // ==============================================================

  return (

    <Box>

      <Button

        startIcon={
          <ArrowBackRounded />
        }

        onClick={
          () =>
            navigate(
              "/threats",
            )
        }

        sx={{
          mb:
            2,
        }}

      >

        Back to Threats

      </Button>


      {
        error
        &&
        (

          <Alert
            severity="warning"
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
        incidentError
        &&
        (

          <Alert
            severity="warning"
            sx={{
              mb:
                2,
            }}
          >

            Incident timeline:
            {" "}
            {incidentError}

          </Alert>
        )
      }


      {/* ========================================================= */}
      {/* HEADER */}
      {/* ========================================================= */}

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
            "flex-start",

          md:
            "center",
        }}

        spacing={2}

        sx={{
          mb:
            3,
        }}

      >

        <Box>

          <Stack

            direction="row"

            spacing={1.5}

            alignItems="center"

          >

            <WarningAmberRounded
              sx={{
                color,

                fontSize:
                  32,
              }}
            />


            <Typography
              variant="h4"
              sx={{
                fontWeight:
                  750,
              }}
            >

              {
                productTitle(
                  threat.title,
                )
              }

            </Typography>

          </Stack>


          <Typography
            sx={{
              color:
                "#94a3b8",

              mt:
                1,

              fontSize:
                13,
            }}
          >

            Detection #
            {
              show(
                threat.detection_id,
              )
            }

            {" · "}

            {category}

            {" · "}

            {
              show(
                threat.device_id,
              )
            }

          </Typography>


          <Stack

            direction="row"

            spacing={1}

            flexWrap="wrap"

            useFlexGap

            sx={{
              mt:
                1.5,
            }}

          >

            <Chip

              label={
                severity
              }

              sx={{
                color,
              }}

              variant="outlined"

            />


            <Chip

              label={
                category
              }

              variant="outlined"

            />


            <Chip

              label={
                humanize(
                  threat.verdict,
                )
              }

              color={
                verdictColor(
                  threat.verdict,
                )
              }

              variant="outlined"

            />


            <Chip

              label={
                humanize(
                  threat.user_state,
                )
              }

              color={
                stateColor(
                  threat.user_state,
                )
              }

              variant="outlined"

            />


            <Chip

              label={
                incidentLinked
                  ? "Incident Linked"
                  : "Standalone Detection"
              }

              color={
                incidentLinked
                  ? "success"
                  : "default"
              }

              variant="outlined"

            />


            {
              relatedIds.length > 1
              &&
              (

                <Chip

                  label={
                    `${relatedIds.length} related incidents`
                  }

                  color="info"

                  variant="outlined"

                />
              )
            }


            {
              threat.visibility
                ?.synthetic ===
                true
              &&
              (

                <Chip

                  label="SYNTHETIC VALIDATION"

                  size="small"

                  variant="outlined"

                />
              )
            }

          </Stack>

        </Box>


        <Button

          variant="contained"

          disabled={
            !incidentId
          }

          startIcon={
            <ShieldRounded />
          }

          onClick={
            () =>
              navigate(
                "/response-simulator",
                {

                  state: {

                    incidentId,

                    detectionId:
                      threat.detection_id,
                  },
                },
              )
          }

        >

          Review Protection

        </Button>

      </Stack>


      {/* ========================================================= */}
      {/* OVERVIEW */}
      {/* ========================================================= */}

      <Box
        sx={{
          display:
            "grid",

          gridTemplateColumns:
            {

              xs:
                "1fr",

              md:
                "repeat(2,1fr)",
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

            <Typography
              variant="h6"
            >

              Detection Risk

            </Typography>


            <Typography
              sx={{
                fontSize:
                  46,

                fontWeight:
                  800,

                color,

                mt:
                  1,
              }}
            >

              {
                risk === null
                  ? "—"
                  : risk
              }


              <Typography
                component="span"
                sx={{
                  fontSize:
                    15,

                  color:
                    "#94a3b8",
                }}
              >

                {
                  risk === null
                    ? ""
                    : " / 100"
                }

              </Typography>

            </Typography>


            {
              risk !==
                null
              &&
              (

                <LinearProgress

                  variant="determinate"

                  value={
                    Math.max(
                      0,
                      Math.min(
                        100,
                        risk,
                      ),
                    )
                  }

                  sx={{
                    height:
                      9,

                    borderRadius:
                      2,

                    background:
                      "#1e293b",
                  }}

                />
              )
            }


            <Typography
              sx={{
                color:
                  "#94a3b8",

                fontSize:
                  12,

                mt:
                  1.5,
              }}
            >

              {
                riskDescription(
                  threat,
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
                  1,
              }}
            >

              {
                fusion
                  ? (
                      `Fusion confidence: ${
                        formatConfidence(
                          confidence,
                        )
                      }`
                    )
                  : (
                      `Detection confidence: ${
                        formatConfidence(
                          confidence,
                        )
                      }`
                    )
              }

            </Typography>

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

            >

              <PsychologyRounded
                sx={{
                  color:
                    "#a78bfa",
                }}
              />


              <Typography
                variant="h6"
              >

                Evidence Corroboration

              </Typography>

            </Stack>


            <Typography
              sx={{
                fontSize:
                  28,

                fontWeight:
                  750,

                mt:
                  2,
              }}
            >

              {
                corroboration.title
              }

            </Typography>


            <Typography
              sx={{
                color:
                  "#94a3b8",

                mt:
                  1,

                fontSize:
                  13,
              }}
            >

              {
                corroboration.detail
              }

            </Typography>


            <Typography
              sx={{
                color:
                  "#64748b",

                mt:
                  1,

                fontSize:
                  12,
              }}
            >

              Correlation describes recorded evidence relationships.
              It is not a calibrated probability and does not
              authorize a protection action.

            </Typography>

          </CardContent>

        </Card>

      </Box>


      {/* ========================================================= */}
      {/* WHAT HAPPENED */}
      {/* ========================================================= */}

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

            <TimelineRounded
              sx={{
                color:
                  "#60a5fa",
              }}
            />


            <Typography
              variant="h6"
            >

              What Happened?

            </Typography>

          </Stack>


          <Typography
            sx={{
              mt:
                2,

              lineHeight:
                1.8,
            }}
          >

            Sentinel-X recorded a
            {" "}

            <strong>

              {
                category
                  .toLowerCase()
              }

            </strong>

            {" "}

            security detection using the
            {" "}

            <strong>

              {
                show(
                  threat.engine,
                )
              }

            </strong>

            {" "}

            detector.

          </Typography>


          <Box
            sx={{
              mt:
                2,
            }}
          >

            <EvidenceGrid
              rows={
                evidenceRows
              }
            />

          </Box>


          <DetailField
            label="Original event"
            value={
              threat.event_id
            }
          />


          <DetailField
            label="Event type"
            value={
              humanize(
                threat.event_type,
              )
            }
          />


          <DetailField
            label="Detected"
            value={
              formatTime(
                threat.timestamp,
              )
            }
          />


          <DetailField
            label="Detection reason"
            value={
              reasons.length
                ? reasons.join(
                    ", ",
                  )
                : (
                    "No specific reason recorded"
                  )
            }
          />


          {
            effectiveIncident
              ? (

                  <Alert
                    severity="info"
                    sx={{
                      mt:
                        2,
                    }}
                  >

                    This detection is linked to primary incident
                    {" "}

                    {
                      show(
                        incidentId,
                      )
                    }

                    .

                    {
                      relatedIds.length > 1
                        ? (
                            ` ${relatedIds.length} related incident records contain this event.`
                          )
                        : ""
                    }

                  </Alert>
                )
              : (

                  <Alert
                    severity="info"
                    sx={{
                      mt:
                        2,
                    }}
                  >

                    This is currently a standalone detection.
                    No correlated incident was recorded for this event.

                  </Alert>
                )
          }


          <Typography
            sx={{
              fontWeight:
                700,

              mt:
                3,

              mb:
                1.5,
            }}
          >

            Recorded Incident Timeline

          </Typography>


          {
            timeline.length
              ? (

                  timeline.map(
                    (
                      item,
                      index,
                    ) => (

                      <TimelineEntry

                        key={
                          item
                            ?.event_id
                          ||
                          index
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

                    {
                      incidentLinked
                        ? (
                            "No detailed timeline was available in the retrieved incident record."
                          )
                        : (
                            "No incident timeline exists because this detection is currently standalone."
                          )
                    }

                  </Alert>
                )
          }

        </CardContent>

      </Card>


      {/* ========================================================= */}
      {/* EVIDENCE BOUNDARIES */}
      {/* ========================================================= */}

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
          >

            Evidence Boundaries

          </Typography>


          <Typography
            sx={{
              color:
                "#94a3b8",

              fontSize:
                12,

              mt:
                1,
            }}
          >

            The canonical contract separates recorded observations
            from later inference. Missing inference does not mean
            that every uncertainty has been resolved.

          </Typography>


          <Box
            sx={{
              display:
                "grid",

              gridTemplateColumns:
                {

                  xs:
                    "1fr",

                  md:
                    "repeat(3,1fr)",
                },

              gap:
                2,

              mt:
                2,
            }}
          >

            <Box
              sx={{
                p:
                  2,

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
                    12,
                }}
              >

                Observed Evidence

              </Typography>


              <Typography
                sx={{
                  fontSize:
                    26,

                  fontWeight:
                    750,

                  mt:
                    0.5,
                }}
              >

                {
                  boundaries
                    .observed
                    .length
                }

              </Typography>

            </Box>


            <Box
              sx={{
                p:
                  2,

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
                    12,
                }}
              >

                Inferred Statements

              </Typography>


              <Typography
                sx={{
                  fontSize:
                    26,

                  fontWeight:
                    750,

                  mt:
                    0.5,
                }}
              >

                {
                  boundaries
                    .inferred
                    .length
                }

              </Typography>

            </Box>


            <Box
              sx={{
                p:
                  2,

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
                    12,
                }}
              >

                Explicit Unknown Items

              </Typography>


              <Typography
                sx={{
                  fontSize:
                    26,

                  fontWeight:
                    750,

                  mt:
                    0.5,
                }}
              >

                {
                  boundaries
                    .unknown
                    .length
                }

              </Typography>

            </Box>

          </Box>


          {
            boundaries
              .inferred
              .length ===
              0
            &&
            (

              <Alert
                severity="info"
                sx={{
                  mt:
                    2,
                }}
              >

                No inference statements are recorded at this
                detection-contract layer. AI Investigation will
                provide incident-level reasoning separately.

              </Alert>
            )
          }

        </CardContent>

      </Card>


      {/* ========================================================= */}
      {/* WHY FLAGGED */}
      {/* ========================================================= */}

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

            <PsychologyRounded
              sx={{
                color:
                  "#a78bfa",
              }}
            />


            <Typography
              variant="h6"
            >

              Why Sentinel-X Flagged This

            </Typography>

          </Stack>


          <Stack
            spacing={1.2}
            sx={{
              mt:
                2,
            }}
          >

            {
              explanations.map(
                (
                  text,
                  index,
                ) => (

                  <Typography

                    key={
                      index
                    }

                    sx={{
                      color:
                        "#cbd5e1",
                    }}

                  >

                    • {text}

                  </Typography>
                ),
              )
            }

          </Stack>


          <Alert
            severity="warning"
            sx={{
              mt:
                2,
            }}
          >

            Detector classification:
            {" "}

            {
              humanize(
                threat.threat_type,
              )
            }

            .

            {" "}

            Canonical verdict:
            {" "}

            <strong>

              {
                humanize(
                  threat.verdict,
                )
              }

            </strong>

            .

            {" "}

            The verdict remains separate from severity and from
            any future protection-policy decision.

          </Alert>


          {/* PROCESS FUSION MODEL EVIDENCE ONLY */}

          {
            hasProcessModels
            &&
            (

              <>

                <Typography
                  variant="h6"
                  sx={{
                    mt:
                      3,

                    mb:
                      1.5,
                  }}
                >

                  Process AI Evidence

                </Typography>


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
                      2,
                  }}
                >

                  <TemporalCard
                    temporal={
                      temporal
                    }
                  />


                  <ModelCard

                    title="Isolation Forest"

                    model={
                      forest
                    }

                    modelType="forest"

                  />


                  <ModelCard

                    title="Autoencoder"

                    model={
                      encoder
                    }

                    modelType="encoder"

                  />

                </Box>


                <Box
                  sx={{
                    mt:
                      2,

                    display:
                      "grid",

                    gridTemplateColumns:
                      {

                        xs:
                          "1fr",

                        md:
                          "repeat(3,1fr)",
                      },

                    gap:
                      1.5,
                  }}
                >

                  <Box
                    sx={{
                      p:
                        1.5,

                      background:
                        "#0f172a",

                      borderRadius:
                        2,

                      border:
                        "1px solid #1e293b",
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

                      Rule score

                    </Typography>


                    <Typography
                      sx={{
                        fontWeight:
                          700,

                        mt:
                          0.5,
                      }}
                    >

                      {
                        show(
                          scores.rule_score,
                        )
                      }

                    </Typography>

                  </Box>


                  <Box
                    sx={{
                      p:
                        1.5,

                      background:
                        "#0f172a",

                      borderRadius:
                        2,

                      border:
                        "1px solid #1e293b",
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

                      Fusion-v3 score

                    </Typography>


                    <Typography
                      sx={{
                        fontWeight:
                          700,

                        mt:
                          0.5,
                      }}
                    >

                      {
                        show(
                          scores.fusion_score,
                        )
                      }

                    </Typography>

                  </Box>


                  <Box
                    sx={{
                      p:
                        1.5,

                      background:
                        "#0f172a",

                      borderRadius:
                        2,

                      border:
                        "1px solid #1e293b",
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

                      Model agreement

                    </Typography>


                    <Typography
                      sx={{
                        fontWeight:
                          700,

                        mt:
                          0.5,

                        overflowWrap:
                          "anywhere",
                      }}
                    >

                      {
                        readableList(
                          scores.ai_agreement,
                        )
                      }

                    </Typography>

                  </Box>

                </Box>


                {
                  hasFeatureEvidence
                  &&
                  (

                    <>

                      <Typography
                        variant="h6"
                        sx={{
                          mt:
                            3,

                          mb:
                            1.5,
                        }}
                      >

                        Features Behind the Alert

                      </Typography>


                      <FeatureEvidence
                        forest={
                          forest
                        }
                        encoder={
                          encoder
                        }
                      />

                    </>
                  )
                }

              </>
            )
          }


          {
            !fusion
            &&
            (

              <Alert
                severity="info"
                sx={{
                  mt:
                    2,
                }}
              >

                This detection was produced by
                {" "}

                {
                  show(
                    threat.engine,
                  )
                }

                .

                {" "}

                Process-only models such as Isolation Forest and
                the process Autoencoder are not shown because
                they are not evidence for this detector.

              </Alert>
            )
          }

        </CardContent>

      </Card>


      {/* ========================================================= */}
      {/* ADVANCED TECHNICAL DETAILS */}
      {/* ========================================================= */}

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

            Advanced Technical Details

          </Typography>

        </AccordionSummary>


        <AccordionDetails>

          <DetailField
            label="Contract schema"
            value={
              threat.schema_version
            }
          />


          <DetailField
            label="Canonical security ID"
            value={
              threat.id
            }
          />


          <DetailField
            label="Detection ID"
            value={
              threat.detection_id
            }
          />


          <DetailField
            label="Event ID"
            value={
              threat.event_id
            }
          />


          <DetailField
            label="Device ID"
            value={
              threat.device_id
            }
          />


          <DetailField
            label="Category"
            value={
              category
            }
          />


          <DetailField
            label="Detector engine"
            value={
              threat.engine
            }
          />


          <DetailField
            label="Threat type"
            value={
              threat.threat_type
            }
          />


          <DetailField
            label="Verdict"
            value={
              threat.verdict
            }
          />


          <DetailField
            label="User state"
            value={
              threat.user_state
            }
          />


          <DetailField
            label="Severity"
            value={
              severity
            }
          />


          <DetailField
            label={
              fusion
                ? "Fusion confidence"
                : "Detection confidence"
            }
            value={
              formatConfidence(
                confidence,
              )
            }
          />


          <DetailField
            label="Confidence semantics"
            value={
              threat
                .confidence_semantics
            }
          />


          <DetailField
            label="Detection risk score"
            value={
              risk
            }
          />


          <DetailField
            label="Detection risk semantics"
            value={
              threat
                ?.risk
                ?.detection
                ?.semantics
            }
          />


          <DetailField
            label="Investigation risk"
            value={
              threat
                ?.risk
                ?.investigation
                ?.score
            }
          />


          <DetailField
            label="Simulation risk"
            value={
              threat
                ?.risk
                ?.simulation
                ?.score
            }
          />


          <DetailField
            label="Primary incident ID"
            value={
              incidentId
            }
          />


          <DetailField
            label="Related incident IDs"
            value={
              relatedIds.length
                ? relatedIds.join(
                    ", ",
                  )
                : null
            }
          />


          <DetailField
            label="Primary incident event count"
            value={
              effectiveIncident
                ?.event_count
              ??
              effectiveIncident
                ?.event_ids
                ?.length
            }
          />


          {
            fusion
            &&
            (

              <>

                <DetailField
                  label="Fusion version"
                  value={
                    process.fusion_version
                  }
                />


                <DetailField
                  label="Rule score"
                  value={
                    scores.rule_score
                  }
                />


                <DetailField
                  label="Temporal score"
                  value={
                    scores.temporal_score
                  }
                />


                <DetailField
                  label="Isolation Forest score"
                  value={
                    scores.isolation_forest_score
                  }
                />


                <DetailField
                  label="Autoencoder score"
                  value={
                    scores.autoencoder_score
                  }
                />


                <DetailField
                  label="Fusion-v3 score"
                  value={
                    scores.fusion_score
                  }
                />


                <DetailField
                  label="AI consensus score"
                  value={
                    scores.ai_consensus_score
                  }
                />


                <DetailField
                  label="Supporting models / signals"
                  value={
                    readableList(
                      scores.ai_agreement,
                    )
                  }
                />


                <DetailField
                  label="Disagreeing models / signals"
                  value={
                    readableList(
                      scores.ai_disagreement,
                    )
                  }
                />

              </>
            )
          }


          <Alert
            severity="info"
            sx={{
              mt:
                2,
            }}
          >

            Technical values are displayed from the canonical
            security contract and persisted incident evidence.
            The page does not invent missing model output.

          </Alert>

        </AccordionDetails>

      </Accordion>


      {/* ========================================================= */}
      {/* PROTECTION */}
      {/* ========================================================= */}

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
                "flex-start",

              md:
                "center",
            }}

            spacing={2}

          >

            <Box>

              <Typography
                variant="h6"
              >

                Protection Review

              </Typography>


              <Typography
                sx={{
                  mt:
                    1,

                  color:
                    "#94a3b8",
                }}
              >

                User state:
                {" "}

                {
                  humanize(
                    threat.user_state,
                  )
                }

              </Typography>


              <Typography
                sx={{
                  color:
                    "#64748b",

                  fontSize:
                    12,

                  mt:
                    1,

                  overflowWrap:
                    "anywhere",
                }}
              >

                Incident ID:
                {" "}

                {
                  show(
                    incidentId,
                  )
                }

              </Typography>


              {
                threat
                  ?.protection
                  ?.available ===
                  false
                &&
                (

                  <Typography
                    sx={{
                      color:
                        "#64748b",

                      fontSize:
                        12,

                      mt:
                        0.5,
                    }}
                  >

                    No protection preview has been evaluated at
                    the canonical detection layer yet.

                  </Typography>
                )
              }

            </Box>


            <Button

              variant="contained"

              startIcon={
                <ScienceRounded />
              }

              disabled={
                !incidentId
              }

              onClick={
                () =>
                  navigate(
                    "/response-simulator",
                    {

                      state: {

                        incidentId,

                        detectionId:
                          threat.detection_id,
                      },
                    },
                  )
              }

            >

              Open Protection Simulator

            </Button>

          </Stack>


          <Typography
            sx={{
              color:
                "#94a3b8",

              fontSize:
                12,

              mt:
                2,
            }}
          >

            Opening the simulator does not execute a real endpoint
            action. Protection simulation validates the incident
            and response candidates independently.

          </Typography>

        </CardContent>

      </Card>

    </Box>
  );
}