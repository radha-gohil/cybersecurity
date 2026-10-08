import {

  useEffect,

  useMemo,

  useState,

} from "react";



import {

  useNavigate,

} from "react-router-dom";



import {

  Alert,

  Box,

  Button,

  Card,

  CardContent,

  Chip,

  CircularProgress,

  Divider,

  Stack,

  Tab,

  Tabs,

  Typography,

} from "@mui/material";



import {

  AccessTimeRounded,

  ArrowForwardRounded,

  DevicesRounded,

  PsychologyRounded,

  ShieldRounded,

  WarningAmberRounded,

} from "@mui/icons-material";



import api, {
  getUserSecurityStatus,
  getUserSecurityThreats,
} from "../api/sentinelApi";





// ================================================================

// CONFIG

// ================================================================



const REFRESH_MS = 10000;



const THREAT_LIMIT = 100;



const CONTRACT_VERSION =

  "sentinelx.security.v1";





// ================================================================

// GENERIC HELPERS

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





function valueOrFallback(

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



  return String(

    value,

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

      (character) =>

        character.toUpperCase(),

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





// ================================================================

// TIME

// ================================================================



function formatTime(

  timestamp,

) {



  if (!timestamp) {



    return "Not reported";

  }



  const parsed =

    new Date(

      timestamp,

    );



  if (

    Number.isNaN(

      parsed.getTime(),

    )

  ) {



    return String(

      timestamp,

    );

  }



  if (

    typeof timestamp ===

      "string" &&

    !/[zZ]$|[+-]\d\d:\d\d$/.test(

      timestamp,

    )

  ) {



    return (

      String(timestamp) +

      " (timezone unspecified)"

    );

  }



  return (

    parsed.toLocaleString()

  );

}





// ================================================================

// CONFIDENCE

// ================================================================



function formatConfidence(

  value,

) {



  if (

    value === null ||

    value === undefined ||

    value === ""

  ) {



    return "Not reported";

  }



  const numeric =

    Number(

      value,

    );



  if (

    !Number.isFinite(

      numeric,

    )

  ) {



    return String(

      value,

    );

  }



  const percentage =

    numeric <= 1

      ? numeric * 100

      : numeric;



  return (

    `${Math.round(

      percentage * 10,

    ) / 10}%`

  );

}





// ================================================================

// SEVERITY

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

// VERDICT COLORS

// ================================================================



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



      return "warning";



    case "SUSPICIOUS":



      return "warning";



    case "SAFE":



    case "BENIGN":



      return "success";



    default:



      return "default";

  }

}





// ================================================================

// USER STATE COLORS

// ================================================================



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



      return "warning";



    case "PROTECTION_FAILED":



      return "error";



    case "NEEDS_ATTENTION":



    case "SUSPICIOUS":



      return "warning";



    default:



      return "default";

  }

}





// ================================================================

// OBSERVED EVIDENCE

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



  const row =

    observedEvidence(

      threat,

    ).find(

      (item) =>

        String(

          item?.type || "",

        ).toUpperCase() ===

        String(

          type || "",

        ).toUpperCase(),

    );



  return object(

    row?.data,

  );

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

        (item) =>

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

            (item) =>

              String(

                item,

              ).replace(

                /_/g,

                " ",

              ),

          );

      }



    } catch {



      // Plain recorded string.

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

// INCIDENT HELPERS

// ================================================================



function incidentIds(

  threat,

) {



  const incident =

    object(

      threat?.incident,

    );



  const related =

    array(

      incident

        .related_incident_ids,

    )

      .filter(Boolean)

      .map(String);



  if (

    related.length

  ) {



    return [

      ...new Set(

        related,

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





function hasIncident(

  threat,

) {



  return (

    incidentIds(

      threat,

    ).length > 0

  );

}





// ================================================================

// CATEGORY-SPECIFIC PRIMARY EVIDENCE

// ================================================================



function getPrimaryEvidence(

  threat,

) {



  const category =

    String(

      threat?.category ||

      "OTHER",

    ).toUpperCase();



  const process =

    evidenceOfType(

      threat,

      "PROCESS",

    );



  const file =

    evidenceOfType(

      threat,

      "FILE",

    );



  const network =

    evidenceOfType(

      threat,

      "NETWORK",

    );



  const registry =

    evidenceOfType(

      threat,

      "REGISTRY",

    );



  const authentication =

    evidenceOfType(

      threat,

      "AUTHENTICATION",

    );



  const system =

    evidenceOfType(

      threat,

      "SYSTEM",

    );



  const startup =

    evidenceOfType(

      threat,

      "STARTUP",

    );





  switch (

    category

  ) {



    case "PROCESS": {



      const name =

        process.process_name ||

        process.name;



      const pid =

        process.pid;



      return {



        label:

          "Process / PID",



        value:

          name

            ? `${name} / ${valueOrFallback(

                pid,

              )}`

            : (

                pid !==

                  undefined &&

                pid !== null

                  ? `PID ${pid}`

                  : "Process evidence recorded"

              ),

      };

    }





    case "FILE":



      return {



        label:

          "File Evidence",



        value:

          file.name ||

          file.path ||

          file.sha256 ||

          "File evidence recorded",

      };





    case "NETWORK": {



      if (

        network.remote_ip

      ) {



        return {



          label:

            "Network Evidence",



          value:

            network.remote_port

              ? (

                  `${network.remote_ip}:`

                  +

                  `${network.remote_port}`

                )

              : String(

                  network.remote_ip,

                ),

        };

      }



      if (

        network.scanned_port_count

      ) {



        return {



          label:

            "Network Evidence",



          value:

            `${network.scanned_port_count} destination ports scanned`,

        };

      }



      if (

        network.connection_rate

      ) {



        return {



          label:

            "Network Evidence",



          value:

            (

              `${network.connection_rate} connections`

              +

              (

                network.unique_remote_count

                  ? (

                      ` / ${network.unique_remote_count}`

                      +

                      " remote hosts"

                    )

                  : ""

              )

            ),

        };

      }



      return {



        label:

          "Network Evidence",



        value:

          "Network activity recorded",

      };

    }





    case "REGISTRY":



      return {



        label:

          "Registry Evidence",



        value:

          registry.key

            ? (

                registry.value_name

                  ? (

                      `${registry.key}`

                      +

                      ` • ${registry.value_name}`

                    )

                  : registry.key

              )

            : "Registry activity recorded",

      };





    case "AUTHENTICATION":



      return {



        label:

          "Authentication",



        value:

          authentication.username ||

          authentication.account ||

          (

            network.remote_ip

              ? (

                  `Source ${network.remote_ip}`

                )

              : "Authentication evidence recorded"

          ),

      };





    case "SYSTEM":



      return {



        label:

          "System Evidence",



        value:

          system.account ||

          system.privilege ||

          humanize(

            threat.event_type,

          ) ||

          "System security event recorded",

      };





    case "STARTUP":



      return {



        label:

          "Startup Entry",



        value:

          startup.entry_name ||

          startup.path ||

          "Startup evidence recorded",

      };





    default: {



      const first =

        observedEvidence(

          threat,

        )[0];



      return {



        label:

          first?.type

            ? (

                `${humanize(

                  first.type,

                )} Evidence`

              )

            : "Security Evidence",



        value:

          humanize(

            threat.event_type ||

            threat.threat_type ||

            "Security detection",

          ),

      };

    }

  }

}





// ================================================================

// PROCESS FUSION

// ================================================================



function isFusionThreat(

  threat,

) {



  return (

    String(

      threat?.model_evidence

        ?.type ||

      "",

    ).toUpperCase() ===

      "PROCESS_FUSION_V3"

  );

}



// ================================================================

// INFO ITEM

// ================================================================



function InfoItem({

  icon,

  label,

  value,

}) {



  return (



    <Box

      sx={{

        p:

          1.7,



        background:

          "#0f172a",



        border:

          "1px solid #1e293b",



        borderRadius:

          2,



        minWidth:

          0,

      }}

    >



      <Stack



        direction="row"



        spacing={1}



        alignItems="center"



      >



        {icon}





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



      </Stack>





      <Typography

        sx={{

          mt:

            0.8,



          fontSize:

            14,



          fontWeight:

            650,



          overflowWrap:

            "anywhere",

        }}

      >



        {

          valueOrFallback(

            value,

          )

        }



      </Typography>



    </Box>

  );

}





// ================================================================

// SUMMARY

// ================================================================



function SummaryCard({

  title,

  count,

  color,

}) {



  return (



    <Card>



      <CardContent

        sx={{

          p:

            2.5,

        }}

      >



        <Typography

          sx={{

            color:

              "#94a3b8",



            fontSize:

              13,

          }}

        >



          {title}



        </Typography>





        <Typography

          sx={{

            fontSize:

              29,



            fontWeight:

              800,



            color,



            mt:

              0.5,

          }}

        >



          {count}



        </Typography>



      </CardContent>



    </Card>

  );

}





// ================================================================

// MODEL SIGNAL

// ================================================================



function ModelSignal({

  title,

  value,

  detail,

}) {



  return (



    <Box

      sx={{

        p:

          1.5,



        border:

          "1px solid #1e293b",



        borderRadius:

          2,



        background:

          "#0f172a",



        minWidth:

          0,

      }}

    >



      <Typography

        sx={{

          fontSize:

            11,



          color:

            "#94a3b8",

        }}

      >



        {title}



      </Typography>





      <Typography

        sx={{

          mt:

            0.5,



          fontSize:

            13,



          fontWeight:

            700,



          overflowWrap:

            "anywhere",

        }}

      >



        {

          valueOrFallback(

            value,

          )

        }



      </Typography>





      {

        detail

        &&

        (



          <Typography

            sx={{

              mt:

                0.4,



              fontSize:

                11,



              color:

                "#64748b",

            }}

          >



            {detail}



          </Typography>

        )

      }



    </Box>

  );

}





// ================================================================

// FUSION EVIDENCE

// ================================================================



function FusionEvidence({

  threat,

}) {



  if (

    !isFusionThreat(

      threat,

    )

  ) {



    return null;

  }



  const model =

    object(

      threat.model_evidence,

    );



  const rules =

    object(

      model.rules,

    );



  const temporal =

    object(

      model.temporal_ai,

    );



  const forest =

    object(

      model.isolation_forest,

    );



  const encoder =

    object(

      model.autoencoder,

    );



  const fusion =

    object(

      model.fusion,

    );



  const consensus =

    object(

      model.consensus,

    );





  return (



    <Box

      sx={{

        mt:

          2,

      }}

    >



      <Typography

        sx={{

          fontWeight:

            700,



          fontSize:

            13,



          mb:

            1,

        }}

      >



        Detection signals



      </Typography>





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

                "repeat(5,minmax(0,1fr))",

            },



          gap:

            1,

        }}

      >



        <ModelSignal



          title="Rules"



          value={

            rules.score ===

              null ||

            rules.score ===

              undefined

              ? "Not reported"

              : `${rules.score}/100`

          }



          detail="Behavioral evidence"



        />





        <ModelSignal



          title="Temporal AI"



          value={

            temporal.available ===

              true

              ? (

                  temporal.score ===

                    null ||

                  temporal.score ===

                    undefined

                    ? (

                        temporal.label ||

                        temporal.severity ||

                        "Reported"

                      )

                    : `${temporal.score}/100`

                )

              : "Not available"

          }



          detail={

            temporal.label ||

            temporal.severity ||

            null

          }



        />





        <ModelSignal



          title="Isolation Forest"



          value={

            forest.available ===

              true

              ? (

                  forest.anomaly_label ||

                  "Reported"

                )

              : "Not available"

          }



          detail={

            forest.available ===

              true &&

            forest.anomaly_confidence !==

              null &&

            forest.anomaly_confidence !==

              undefined

              ? (

                  `${forest.anomaly_confidence}`

                  +

                  "/100 anomaly confidence"

                )

              : null

          }



        />





        <ModelSignal



          title="Autoencoder"



          value={

            encoder.available ===

              true

              ? (

                  encoder.anomaly_label ||

                  "Reported"

                )

              : "Not available"

          }



          detail={

            encoder.available ===

              true &&

            encoder.anomaly_confidence !==

              null &&

            encoder.anomaly_confidence !==

              undefined

              ? (

                  `${encoder.anomaly_confidence}`

                  +

                  "/100 anomaly confidence"

                )

              : null

          }



        />





        <ModelSignal



          title="Fusion-v3"



          value={

            fusion.score ===

              null ||

            fusion.score ===

              undefined

              ? "Not reported"

              : `${fusion.score}/100`

          }



          detail={

            fusion.severity ||

            null

          }



        />



      </Box>





      {

        consensus.label

        &&

        (



          <Typography

            sx={{

              color:

                "#94a3b8",



              fontSize:

                11,



              mt:

                1,

            }}

          >



            Model consensus:

            {" "}

            {

              humanize(

                consensus.label,

              )

            }



          </Typography>

        )

      }



    </Box>

  );

}





// ================================================================

// 7D.9 — MATCH USER SECURITY SNAPSHOT

// ================================================================

function findUserSecuritySnapshot(

  threat,

  snapshots,

) {



  if (

    !threat

    ||

    !Array.isArray(

      snapshots,

    )

  ) {



    return null;

  }



  const threatId =

    String(

      threat.id ||

      "",

    );



  const incidentId =

    String(

      threat.incident_id ||

      threat?.incident?.incident_id ||

      "",

    );



  const directMatch =

    snapshots.find(

      (snapshot) =>

        String(

          snapshot?.security_id ||

          "",

        )

        ===

        threatId,

    );



  if (

    directMatch

  ) {



    return directMatch;

  }



  if (

    incidentId

  ) {



    const incidentMatch =

      snapshots.find(

        (snapshot) =>

          String(

            snapshot?.incident_id ||

            "",

          )

          ===

          incidentId,

      );



    if (

      incidentMatch

    ) {



      return incidentMatch;

    }

  }



  return null;

}



// ================================================================

// THREAT CARD

// ================================================================



function ThreatCard({

  threat,

  onView,

  aiSnapshot = null,

}) {



  const severity =

    String(

      threat.severity ||

      "UNKNOWN",

    ).toUpperCase();



  const color =

    severityColor(

      severity,

    );



  const primaryEvidence =

    getPrimaryEvidence(

      threat,

    );



  const reasons =

    detectionReasons(

      threat,

    );



  const reason =

    reasons.length

      ? reasons.join(

          ", ",

        )

      : (

          "No specific detection reason "

          +

          "was recorded."

        );



  const relatedIds =

    incidentIds(

      threat,

    );



  const linked =

    relatedIds.length > 0;



  const detectionRisk =

    threat.risk

      ?.detection

      ?.score;



  const fusion =

    isFusionThreat(

      threat,

    );





  return (



    <Card

      sx={{

        borderColor:

          `${color}55`,



        transition:

          "0.2s",



        "&:hover":

          {



            borderColor:

              color,



            transform:

              "translateY(-1px)",

          },

      }}

    >



      <CardContent

        sx={{

          p:

            3,

        }}

      >



        {/* ===================================================== */}

        {/* HEADER */}

        {/* ===================================================== */}



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



          <Stack



            direction="row"



            spacing={2}



          >



            <Box

              sx={{

                width:

                  46,



                height:

                  46,



                borderRadius:

                  2,



                background:

                  `${color}18`,



                color,



                display:

                  "flex",



                justifyContent:

                  "center",



                alignItems:

                  "center",



                flexShrink:

                  0,

              }}

            >



              <WarningAmberRounded />



            </Box>





            <Box

              sx={{

                minWidth:

                  0,

              }}

            >



              <Typography

                sx={{

                  fontWeight:

                    750,



                  fontSize:

                    18,



                  overflowWrap:

                    "anywhere",

                }}

              >



                {

                  productTitle(

                    threat.title,

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

                    0.5,

                }}

              >



                Detection #

                {

                  valueOrFallback(

                    threat.detection_id,

                  )

                }



                {" | "}



                {

                  valueOrFallback(

                    threat.engine,

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

                severity

              }



              size="small"



              sx={{

                color,



                border:

                  `1px solid ${color}`,



                background:

                  `${color}18`,

              }}



            />





            <Chip



              label={

                humanize(

                  threat.category,

                )

              }



              size="small"



              variant="outlined"



            />





            <Chip



              label={

                humanize(

                  threat.verdict,

                )

              }



              size="small"



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



              size="small"



              color={

                stateColor(

                  threat.user_state,

                )

              }



              variant="outlined"



            />



            {

              aiSnapshot

              &&

              (



                <Chip

                  label={

                    `AI ${humanize(

                      aiSnapshot.status ||

                      "READY",

                    )}`

                  }

                  size="small"

                  icon={

                    <PsychologyRounded />

                  }

                  sx={{

                    color:

                      "#a78bfa",

                    border:

                      "1px solid rgba(167,139,250,0.45)",

                    background:

                      "rgba(139,92,246,0.10)",

                    fontWeight:

                      700,

                  }}

                />

              )

            }



          </Stack>



        </Stack>





        {/* ===================================================== */}

        {/* PRIMARY INFORMATION */}

        {/* ===================================================== */}



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

              3,

          }}

        >



          <InfoItem



            icon={

              <DevicesRounded

                fontSize="small"

              />

            }



            label={

              primaryEvidence.label

            }



            value={

              primaryEvidence.value

            }



          />





          <InfoItem



            icon={

              <ShieldRounded

                fontSize="small"

              />

            }



            label="Detection Risk"



            value={

              detectionRisk ===

                null ||

              detectionRisk ===

                undefined

                ? "Not reported"

                : `${detectionRisk}/100`

            }



          />





          <InfoItem



            icon={

              <PsychologyRounded

                fontSize="small"

              />

            }



            label={

              fusion

                ? "Fusion Confidence"

                : "Detection Confidence"

            }



            value={

              formatConfidence(

                threat.confidence,

              )

            }



          />





          <InfoItem



            icon={

              <AccessTimeRounded

                fontSize="small"

              />

            }



            label="Detected"



            value={

              formatTime(

                threat.timestamp,

              )

            }



          />



        </Box>





        {/* ===================================================== */}

        {/* RISK SEMANTICS */}

        {/* ===================================================== */}



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

            detectionRisk ===

              null ||

            detectionRisk ===

              undefined

              ? (

                  "No detector risk score was recorded."

                )

              : (

                  "Detection risk is a detector score, not a calibrated probability of attack."

                )

          }



        </Typography>





        {/* ===================================================== */}

        {/* RECORDED REASON */}

        {/* ===================================================== */}



        <Box

          sx={{

            mt:

              2,

          }}

        >



          <Typography

            sx={{

              fontWeight:

                700,



              fontSize:

                13,



              mb:

                0.7,

            }}

          >



            Recorded detection reason



          </Typography>





          <Typography

            sx={{

              fontSize:

                13,



              color:

                "#cbd5e1",



              overflowWrap:

                "anywhere",

            }}

          >



            {reason}



          </Typography>



        </Box>





        {/* ===================================================== */}

        {/* PROCESS MODEL EVIDENCE */}

        {/* ===================================================== */}



        <FusionEvidence

          threat={

            threat

          }

        />





        <Divider

          sx={{

            my:

              2,

          }}

        />





        {/* ===================================================== */}

        {/* INCIDENT RELATIONSHIP */}

        {/* ===================================================== */}



        <Stack



          direction={{

            xs:

              "column",



            sm:

              "row",

          }}



          alignItems={{

            xs:

              "stretch",



            sm:

              "center",

          }}



          justifyContent="space-between"



          spacing={2}



        >



          <Box

            sx={{

              minWidth:

                0,

            }}

          >



            <Typography

              sx={{

                fontSize:

                  12,



                color:

                  "#94a3b8",

              }}

            >



              {

                linked

                  ? (

                      relatedIds.length > 1

                        ? "Related incidents: "

                        : "Related incident: "

                    )

                  : "Correlation: "

              }



              {

                linked

                  ? relatedIds.join(

                      ", ",

                    )

                  : "No correlated incident"

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

                linked

                  ? (

                      relatedIds.length > 1

                        ? (

                            `${relatedIds.length} related incident records were found. `

                            +

                            "The canonical primary incident will open first."

                          )

                        : (

                            "This detection is linked to a recorded security incident."

                          )

                    )

                  : (

                      "This detection is currently standalone and has not been correlated into an incident."

                    )

              }



            </Typography>





            {

              threat.visibility

                ?.synthetic ===

                true

              &&

              (



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



                  Synthetic validation evidence



                </Typography>

              )

            }



          </Box>





          <Button



            variant="outlined"



            endIcon={

              <ArrowForwardRounded />

            }



            onClick={

              onView

            }



            sx={{

              flexShrink:

                0,

            }}



          >



            View Threat



          </Button>



        </Stack>



      </CardContent>



    </Card>

  );

}





// ================================================================

// PAGE

// ================================================================



export default function Threats() {



  const navigate =

    useNavigate();





  const [

    tab,

    setTab,

  ] =

    useState(

      "ALL",

    );





  const [

    threats,

    setThreats,

  ] =

    useState(

      [],

    );



  // ================================================================

  // 7D.9 — USER-FACING AI SECURITY LAYER

  // ================================================================



  const [

    aiSecurityStatus,

    setAiSecurityStatus,

  ] =

    useState(

      null,

    );





  const [

    aiSecurityThreats,

    setAiSecurityThreats,

  ] =

    useState(

      [],

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

    contractWarning,

    setContractWarning,

  ] =

    useState(

      "",

    );





  const [

    updated,

    setUpdated,

  ] =

    useState(

      null,

    );





  // ==============================================================

  // LOAD CANONICAL THREAT FEED

  // ==============================================================



  useEffect(

    () => {



      let active =

        true;



      let busy =

        false;





      async function load() {



        if (

          busy

        ) {



          return;

        }



        busy =

          true;





        try {



          const response =

            await api.get(

              "/security/threats",

              {

                params: {

                  limit:

                    THREAT_LIMIT,

                },

              },

            );





          if (

            !active

          ) {



            return;

          }





          const payload =

            response.data ||

            {};





          // ------------------------------------------------------

          // SCHEMA CHECK

          // ------------------------------------------------------



          if (

            payload.schema_version

            !==

            CONTRACT_VERSION

          ) {



            setContractWarning(

              (

                "Unexpected security contract version: "

                +

                valueOrFallback(

                  payload.schema_version,

                  "missing",

                )

              ),

            );



          } else if (

            payload.contract_valid

            !==

            true

          ) {



            setContractWarning(

              (

                "The security feed contains "

                +

                valueOrFallback(

                  payload.invalid_contract_count,

                  0,

                )

                +

                " invalid canonical contract object(s)."

              ),

            );



          } else {



            setContractWarning(

              "",

            );

          }





          // ------------------------------------------------------

          // USER-VISIBLE CANONICAL OBJECTS

          // ------------------------------------------------------



          const rows =

            array(

              payload.threats,

            )

              .filter(

                (item) =>

                  item &&

                  item.visibility

                    ?.user_visible

                    !==

                    false,

              );





          setThreats(

            rows,

          );



          // ============================================================

          // OPTIONAL 7D.9 AI USER SECURITY DATA

          // ============================================================

          // The canonical threat feed remains the primary data source.

          // Failure of the AI layer must never break this page.



          try {



            const [

              aiStatusResult,

              aiThreatResult,

            ] =

              await Promise.allSettled([

                getUserSecurityStatus(),

                getUserSecurityThreats(

                  THREAT_LIMIT,

                ),

              ]);





            if (

              !active

            ) {



              return;

            }





            if (

              aiStatusResult.status

              ===

              "fulfilled"

            ) {



              setAiSecurityStatus(

                aiStatusResult.value,

              );



            }

            else {



              console.warn(

                "7D.9 user security status unavailable:",

                aiStatusResult.reason,

              );

            }





            if (

              aiThreatResult.status

              ===

              "fulfilled"

            ) {



              setAiSecurityThreats(

                array(

                  aiThreatResult

                    .value

                    ?.threats,

                ),

              );



            }

            else {



              console.warn(

                "7D.9 user security threat feed unavailable:",

                aiThreatResult.reason,

              );

            }



          }

          catch (

            aiError

          ) {



            console.warn(

              "Optional AI security integration unavailable:",

              aiError,

            );

          }





          setUpdated(

            new Date(),

          );





          setError(

            "",

          );



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

              "Unable to retrieve the canonical security threat feed.",

            );

          }



        } finally {



          busy =

            false;



          if (

            active

          ) {



            setLoading(

              false,

            );

          }

        }

      }





      load();





      const interval =

        window.setInterval(

          load,

          REFRESH_MS,

        );





      return (

        () => {



          active =

            false;



          window.clearInterval(

            interval,

          );

        }

      );



    },

    [],

  );





  // ================================================================

  // 7D.9 AI STATUS

  // ================================================================



  const aiSecurityReady =

    String(

      aiSecurityStatus?.status ||

      "",

    )

      .toUpperCase()

    ===

    "READY";





  const aiExplanationCount =

    aiSecurityThreats.length;





  // ==============================================================

  // COUNTS

  // ==============================================================



  const highCount =

    useMemo(

      () =>

        threats.filter(

          (threat) => {



            const severity =

              String(

                threat.severity ||

                "",

              ).toUpperCase();



            return (

              severity ===

                "HIGH"

              ||

              severity ===

                "CRITICAL"

            );

          },

        ).length,



      [

        threats,

      ],

    );





  const linkedCount =

    useMemo(

      () =>

        threats.filter(

          (

            threat,

          ) =>

            hasIncident(

              threat,

            ),

        ).length,



      [

        threats,

      ],

    );





  const standaloneCount =

    threats.length -

    linkedCount;





  // ==============================================================

  // FILTERED DISPLAY

  // ==============================================================



  const displayed =

    useMemo(

      () => {



        if (

          tab ===

          "HIGH"

        ) {



          return threats.filter(

            (

              threat,

            ) => {



              const severity =

                String(

                  threat.severity ||

                  "",

                ).toUpperCase();



              return (

                severity ===

                  "HIGH"

                ||

                severity ===

                  "CRITICAL"

              );

            },

          );

        }





        if (

          tab ===

          "LINKED"

        ) {



          return threats.filter(

            (

              threat,

            ) =>

              hasIncident(

                threat,

              ),

          );

        }





        if (

          tab ===

          "STANDALONE"

        ) {



          return threats.filter(

            (

              threat,

            ) =>

              !hasIncident(

                threat,

              ),

          );

        }





        return threats;



      },



      [

        threats,

        tab,

      ],

    );





  // ==============================================================

  // OPEN THREAT

  // ==============================================================



  function openThreat(

    threat,

  ) {



    navigate(

      `/threats/${encodeURIComponent(

        threat.id,

      )}`,

      {

        state: {

          canonicalThreat:

            threat,

        },

      },

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



      <Box

        sx={{

          mb:

            3,

        }}

      >



        <Typography

          variant="h4"

          sx={{

            fontWeight:

              750,

          }}

        >



          Threats



        </Typography>





        <Typography

          sx={{

            color:

              "#94a3b8",



            mt:

              0.5,

          }}

        >



          Security detections that may require attention



        </Typography>





        <Typography

          sx={{

            color:

              "#64748b",



            mt:

              0.6,



            fontSize:

              12,

          }}

        >



          An anomaly or suspicious signal is not automatically

          a confirmed attack. Sentinel-X separates detector

          evidence, verdict, severity and protection state.



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

            size="small"

            label={

              aiSecurityReady

                ?

                "AI SECURITY READY"

                :

                "AI SECURITY UNAVAILABLE"

            }

            sx={{

              color:

                aiSecurityReady

                  ?

                  "#22c55e"

                  :

                  "#f59e0b",

              background:

                aiSecurityReady

                  ?

                  "rgba(34,197,94,0.10)"

                  :

                  "rgba(245,158,11,0.10)",

              fontWeight:

                700,

            }}

          />





          <Chip

            size="small"

            label={

              `AI EXPLANATIONS ${aiExplanationCount}`

            }

            sx={{

              color:

                "#8b5cf6",

              background:

                "rgba(139,92,246,0.10)",

              fontWeight:

                700,

            }}

          />



        </Stack>



      </Box>





      {/* ========================================================= */}

      {/* SUMMARY */}

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

                "repeat(3,1fr)",

            },



          gap:

            2,



          mb:

            3,

        }}

      >



        <SummaryCard



          title="High-Priority Threats"



          count={

            highCount

          }



          color="#f97316"



        />





        <SummaryCard



          title="Incident-Linked Threats"



          count={

            linkedCount

          }



          color="#22c55e"



        />





        <SummaryCard



          title="Visible Threats"



          count={

            threats.length

          }



          color="#60a5fa"



        />



      </Box>





      {/* ========================================================= */}

      {/* FILTERS */}

      {/* ========================================================= */}



      <Card

        sx={{

          mb:

            2,

        }}

      >



        <Tabs



          value={

            tab

          }



          onChange={

            (

              _,

              next,

            ) =>

              setTab(

                next,

              )

          }



          variant="scrollable"



          scrollButtons="auto"



        >



          <Tab



            value="ALL"



            label={

              `All (${threats.length})`

            }



          />





          <Tab



            value="HIGH"



            label={

              `High Priority (${highCount})`

            }



          />





          <Tab



            value="LINKED"



            label={

              `Incident Linked (${linkedCount})`

            }



          />





          <Tab



            value="STANDALONE"



            label={

              `Standalone (${standaloneCount})`

            }



          />



        </Tabs>



      </Card>





      {/* ========================================================= */}

      {/* CONTRACT / API STATUS */}

      {/* ========================================================= */}



      {

        contractWarning

        &&

        (



          <Alert

            severity="warning"

            sx={{

              mb:

                2,

            }}

          >



            {contractWarning}



          </Alert>

        )

      }





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





      {/* ========================================================= */}

      {/* LOADING */}

      {/* ========================================================= */}



      {

        loading

        &&

        (



          <Box

            sx={{

              py:

                5,



              textAlign:

                "center",

            }}

          >



            <CircularProgress />





            <Typography

              sx={{

                mt:

                  2,



                color:

                  "#94a3b8",



                fontSize:

                  12,

              }}

            >



              Loading canonical security threats...



            </Typography>



          </Box>

        )

      }





      {/* ========================================================= */}

      {/* EMPTY */}

      {/* ========================================================= */}



      {

        !loading

        &&

        !displayed.length

        &&

        (



          <Alert

            severity="info"

          >



            No security threats match this filter.



          </Alert>

        )

      }





      {/* ========================================================= */}

      {/* THREATS */}

      {/* ========================================================= */}



      <Stack

        spacing={2}

      >



        {

          displayed.map(

            (

              threat,

            ) => {



              const aiSnapshot =

                findUserSecuritySnapshot(

                  threat,

                  aiSecurityThreats,

                );





              return (



                <ThreatCard



                  key={

                    threat.id

                  }



                  threat={

                    threat

                  }



                  aiSnapshot={

                    aiSnapshot

                  }



                  onView={

                    () =>

                      openThreat(

                        threat,

                      )

                  }



                />

              );

            },

          )

        }



      </Stack>





      {/* ========================================================= */}

      {/* FOOTER */}

      {/* ========================================================= */}



      <Typography

        sx={{

          color:

            "#64748b",



          fontSize:

            12,



          mt:

            3,

        }}

      >



        Showing

        {" "}

        {threats.length}

        {" "}

        user-visible canonical security objects.

        Internal regression records are filtered by the backend.

        Data refreshes every 10 seconds.



        {

          updated

            ? (

                ` Last updated: ${

                  updated.toLocaleTimeString()

                }.`

              )

            : ""

        }



      </Typography>



    </Box>

  );

}