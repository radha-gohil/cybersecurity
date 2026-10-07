import AIStoryboard from "../components/AIStoryboard";
import { useCallback, useEffect, useMemo, useState, } from "react";
import { useLocation } from "react-router-dom";

import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
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
    DevicesRounded,
    HubRounded,
    PauseRounded,
    PlayArrowRounded,
    PsychologyRounded,
    RefreshRounded,
    ReplayRounded,
    ScienceRounded,
    ShieldRounded,
    SkipNextRounded,
    SkipPreviousRounded,
    WarningAmberRounded,
} from "@mui/icons-material";

import api from "../api/sentinelApi";


// ============================================================
// CONFIGURATION
// ============================================================

const INCIDENT_LIMIT = 1000;

const COLORS = {
    process: "#a78bfa",
    file: "#38bdf8",
    network: "#f59e0b",
    persistence: "#22c55e",
    isolation_adjustment: "#fb7185",
};

const COMPONENTS = [
    [
        "process",
        "Process",
    ],
    [
        "file",
        "File",
    ],
    [
        "network",
        "Network",
    ],
    [
        "persistence",
        "Registry / Persistence",
    ],
    [
        "isolation_adjustment",
        "Isolation adjustment",
    ],
];


// ============================================================
// GENERIC HELPERS
// ============================================================

function object(value) {
    return (
        value
        &&
        typeof value === "object"
        &&
        !Array.isArray(value)
    )
        ? value
        : {};
}


function array(value) {
    return Array.isArray(value)
        ? value
        : [];
}


function number(value) {
    if (
        value === null
        ||
        value === undefined
        ||
        value === ""
    ) {
        return null;
    }

    const n = Number(value);

    return Number.isFinite(n)
        ? n
        : null;
}


function display(
    value,
    fallback = "Not available",
) {
    if (
        value === null
        ||
        value === undefined
        ||
        value === ""
    ) {
        return fallback;
    }

    return String(value);
}


function pretty(value) {
    return display(value).replaceAll(
        "_",
        " ",
    );
}


function errorText(error) {
    const detail =
        error?.response?.data?.detail;

    return typeof detail === "string"
        ? detail
        : (
            error?.message
            ||
            "Unable to retrieve Digital Twin information."
        );
}


function compactId(value) {
    const text =
        String(value || "");

    return text.length > 32
        ? `${text.slice(0, 14)}...${text.slice(-10)}`
        : text;
}


function impactColor(value) {
    const key =
        String(value || "").toUpperCase();

    return {
        HIGH: "#ef4444",
        MEDIUM: "#f59e0b",
        LOW: "#22c55e",
        MINIMAL: "#22c55e",
    }[key] || "#94a3b8";
}


// ============================================================
// USER-FACING ACTION LABELS
// ============================================================

function friendlyActionName(value) {
    const key =
        String(value || "").toUpperCase();

    const mapping = {
        BASELINE:
            "Recorded baseline",

        QUARANTINE_FILE:
            "Quarantine suspicious file",

        TERMINATE_PROCESS:
            "Stop suspicious process",

        BLOCK_NETWORK:
            "Block suspicious network connection",

        REMEDIATE_PERSISTENCE:
            "Remove persistence mechanism",

        ISOLATE_ENDPOINT:
            "Isolate device",
    };

    return (
        mapping[key]
        ||
        pretty(value)
    );
}


function componentValue(
    components,
    key,
) {
    return number(
        object(components)[key],
    );
}


// ============================================================
// CANONICAL PLAN NORMALIZATION
// ============================================================

function normalizePlan(
    raw,
    index,
    baseline,
) {
    const plan =
        object(raw);

    const disruption =
        object(
            plan.modeled_disruption,
        );

    return {
        id:
            String(
                plan.plan_id
                ||
                `DT-PLAN-${index + 1}`,
            ),

        title:
            plan.display_name
            ||
            plan.technical_name
            ||
            plan.plan_id
            ||
            "Virtual Protection Plan",

        description:
            plan.description
            ||
            "Read-only virtual protection comparison.",

        actions:
            array(
                plan.actions,
            ),

        actionResults:
            [],

        playback:
            array(
                plan.playback,
            ),

        before:
            number(
                plan.initial_risk_score,
            )
            ??
            baseline,

        after:
            number(
                plan.residual_risk_score,
            ),

        reduction:
            number(
                plan.risk_reduction_percentage,
            ),

        score:
            number(
                plan.ranking_score,
            ),

        impact:
            String(
                disruption.impact_level
                ||
                "UNKNOWN",
            ).toUpperCase(),

        impactReasons:
            array(
                disruption.reasons,
            ),

        recommendedDecision:
            plan.recommended_decision,

        baselineComponents:
            object(
                plan.baseline_components,
            ),

        residualComponents:
            object(
                plan.residual_components,
            ),

        failures:
            array(
                plan.virtual_action_failures,
            ),

        limitations:
            array(
                plan.limitations,
            ),

        scoreType:
            plan.ranking_semantics
            ||
            "HEURISTIC_RANKING_SCORE",

        reductionSemantics:
            plan.reduction_semantics
            ||
            "REDUCTION_OF_MODELED_COMPONENTS",

        hypothetical:
            plan.hypothetical === true,

        approvalEligible:
            plan.approval_eligible === true,

        realModified:
            plan.real_endpoint_modified === true,
    };
}


// ============================================================
// RESULT ROW
// ============================================================

function ResultRow({
    label,
    value,
    color,
}) {
    return (
        <Stack
            direction="row"
            justifyContent="space-between"
            alignItems="flex-start"
            spacing={2}
            sx={{
                py: 0.8,
            }}
        >
            <Typography
                sx={{
                    color: "#94a3b8",
                    fontSize: 12,
                }}
            >
                {label}
            </Typography>

            <Typography
                sx={{
                    color:
                        color
                        ||
                        "#e2e8f0",

                    fontSize: 12,
                    fontWeight: 700,
                    textAlign: "right",
                    overflowWrap: "anywhere",
                }}
            >
                {display(value)}
            </Typography>
        </Stack>
    );
}


// ============================================================
// METRIC
// ============================================================

function Metric({
    label,
    value,
    color = "#93c5fd",
}) {
    return (
        <Card
            sx={{
                height: "100%",
            }}
        >
            <CardContent
                sx={{
                    p: 2.5,
                }}
            >
                <Typography
                    sx={{
                        color: "#94a3b8",
                        fontSize: 12,
                    }}
                >
                    {label}
                </Typography>

                <Typography
                    sx={{
                        color,
                        mt: 0.7,
                        fontSize: 26,
                        fontWeight: 800,
                        overflowWrap: "anywhere",
                    }}
                >
                    {display(
                        value,
                        "—",
                    )}
                </Typography>
            </CardContent>
        </Card>
    );
}


// ============================================================
// RISK BREAKDOWN
// ============================================================

function RiskBreakdown({
    title,
    components,
    emptyMessage =
        "Risk components were not recorded.",
}) {
    const values =
        object(components);

    const hasValues =
        COMPONENTS.some(
            ([key]) =>
                number(
                    values[key],
                ) !== null,
        );

    return (
        <Box
            sx={{
                p: 2.5,
                bgcolor: "#0f172a",
                borderRadius: "14px",
                border: "1px solid #1e293b",
            }}
        >
            <Typography
                sx={{
                    fontWeight: 700,
                    mb: 2,
                }}
            >
                {title}
            </Typography>

            {!hasValues ? (
                <Typography
                    sx={{
                        fontSize: 12,
                        color: "#94a3b8",
                    }}
                >
                    {emptyMessage}
                </Typography>
            ) : (
                <Stack
                    spacing={2}
                >
                    {COMPONENTS.map(
                        (
                            [
                                key,
                                label,
                            ],
                        ) => {
                            const value =
                                componentValue(
                                    values,
                                    key,
                                );

                            if (
                                value === null
                            ) {
                                return null;
                            }

                            const color =
                                COLORS[key];

                            return (
                                <Box
                                    key={key}
                                >
                                    <Stack
                                        direction="row"
                                        justifyContent="space-between"
                                        spacing={1}
                                        sx={{
                                            mb: 0.7,
                                        }}
                                    >
                                        <Typography
                                            sx={{
                                                fontSize: 12,
                                                color: "#cbd5e1",
                                            }}
                                        >
                                            {label}
                                        </Typography>

                                        <Typography
                                            sx={{
                                                fontSize: 12,
                                                color,
                                                fontWeight: 700,
                                            }}
                                        >
                                            {
                                                value > 0
                                                    ? "+"
                                                    : ""
                                            }

                                            {value}
                                        </Typography>
                                    </Stack>

                                    <LinearProgress
                                        variant="determinate"
                                        value={
                                            Math.min(
                                                Math.abs(
                                                    value,
                                                ),
                                                100,
                                            )
                                        }
                                        sx={{
                                            height: 8,
                                            borderRadius: 5,
                                            bgcolor: "#233047",

                                            "& .MuiLinearProgress-bar":
                                                {
                                                    bgcolor:
                                                        color,
                                                },
                                        }}
                                    />
                                </Box>
                            );
                        },
                    )}
                </Stack>
            )}

            <Typography
                sx={{
                    color: "#64748b",
                    mt: 2,
                    fontSize: 11,
                }}
            >
                Component values are heuristic contributions.
                They are not calibrated threat probabilities.
            </Typography>
        </Box>
    );
}


// ============================================================
// EVIDENCE OVERVIEW
// ============================================================

function EvidenceOverview({
    decision,
}) {
    const counts =
        object(
            decision?.evidence_counts,
        );

    const validation =
        object(
            decision?.evidence_validation,
        );

    const validationOnly =
        validation.validation_only ===
        true;

    const status =
        String(
            decision
                ?.investigation
                ?.status
            ||
            "UNKNOWN",
        ).toUpperCase();

    const passed =
        validation.passed === true;

    const reasons =
        array(
            validation.reasons,
        );

    const rejected =
        array(
            validation.rejected_reasons,
        );

    return (
        <Card
            sx={{
                mb: 3,
            }}
        >
            <CardContent
                sx={{
                    p: 3,
                }}
            >
                <Stack
                    direction="row"
                    spacing={1}
                    alignItems="center"
                    flexWrap="wrap"
                    sx={{
                        mb: 2,
                    }}
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
                        Investigation Evidence
                    </Typography>

                    <Chip
                        label={status}
                        color={
                            status ===
                            "COMPLETED"
                                ? "success"
                                : "warning"
                        }
                        size="small"
                    />

                    <Chip
                        label="READ-ONLY PREVIEW"
                        color="info"
                        size="small"
                    />

                    {
                        validationOnly
                        &&
                        (
                            <Chip
                                label="VALIDATION ONLY"
                                color="warning"
                                variant="outlined"
                                size="small"
                            />
                        )
                    }
                </Stack>

                <Box
                    sx={{
                        display: "grid",

                        gridTemplateColumns:
                            {
                                xs:
                                    "repeat(2,minmax(0,1fr))",

                                md:
                                    "repeat(4,minmax(0,1fr))",
                            },

                        gap: 2,
                    }}
                >
                    <Metric
                        label="Processes"
                        value={
                            counts.processes
                            ??
                            0
                        }
                        color={
                            COLORS.process
                        }
                    />

                    <Metric
                        label="Files"
                        value={
                            counts.files
                            ??
                            0
                        }
                        color={
                            COLORS.file
                        }
                    />

                    <Metric
                        label="Network"
                        value={
                            counts.network_connections
                            ??
                            0
                        }
                        color={
                            COLORS.network
                        }
                    />

                    <Metric
                        label="Registry"
                        value={
                            counts.registry_artifacts
                            ??
                            0
                        }
                        color={
                            COLORS.persistence
                        }
                    />
                </Box>

                <Alert
                    severity={
                        passed
                            ? "info"
                            : "warning"
                    }
                    sx={{
                        mt: 2,
                    }}
                >
                    Evidence validation:{" "}

                    <strong>
                        {
                            passed
                                ? "PASSED"
                                : "NOT PASSED"
                        }
                    </strong>
                    .

                    {" "}

                    These counts represent recorded entities
                    available to the virtual evidence model.
                    They do not independently prove malicious intent.
                </Alert>

                <Box
                    sx={{
                        display: "grid",

                        gridTemplateColumns:
                            {
                                xs:
                                    "1fr",

                                md:
                                    "repeat(2,1fr)",
                            },

                        gap: 2,
                        mt: 2,
                    }}
                >
                    <Box>
                        <ResultRow
                            label="Qualifying events"
                            value={
                                validation
                                    .qualifying_event_count
                            }
                        />

                        <ResultRow
                            label="Rejected events"
                            value={
                                validation
                                    .rejected_event_count
                                ??
                                "Not reported"
                            }
                        />

                        <ResultRow
                            label="Production eligible"
                            value={
                                validation
                                    .production_eligible ===
                                true
                                    ? "YES"
                                    : "NO"
                            }
                        />
                    </Box>

                    <Box>
                        <ResultRow
                            label="Investigation risk"
                            value={
                                passed
                                &&
                                status ===
                                "COMPLETED"
                                    ? decision
                                        ?.risk
                                        ?.investigation
                                        ?.score
                                    : "Unvalidated"
                            }
                        />

                        <ResultRow
                            label="Virtual plans available"
                            value={
                                Number(
                                    decision
                                        ?.protection
                                        ?.plans_evaluated
                                    ||
                                    0,
                                )
                            }
                        />
                    </Box>
                </Box>

                {
                    reasons.map(
                        (
                            reason,
                            index,
                        ) => (
                            <Typography
                                key={
                                    `reason-${index}`
                                }
                                sx={{
                                    color:
                                        "#fbbf24",

                                    fontSize:
                                        12,

                                    mt:
                                        1,
                                }}
                            >
                                • {reason}
                            </Typography>
                        ),
                    )
                }

                {
                    !!rejected.length
                    &&
                    (
                        <Stack
                            direction="row"
                            flexWrap="wrap"
                            gap={1}
                            sx={{
                                mt: 2,
                            }}
                        >
                            {
                                rejected.map(
                                    (
                                        reason,
                                        index,
                                    ) => (
                                        <Chip
                                            key={
                                                `rejected-${index}`
                                            }
                                            size="small"
                                            label={
                                                reason
                                            }
                                        />
                                    ),
                                )
                            }
                        </Stack>
                    )
                }
            </CardContent>
        </Card>
    );
}


// ============================================================
// PLAN ACTION ITEM
// ============================================================

function ActionItem({
    action,
}) {
    const item =
        object(
            action,
        );

    const rawName =
        typeof action ===
        "string"
            ? action
            : (
                item.action_type
                ||
                item.action
                ||
                "UNKNOWN_ACTION"
            );

    return (
        <Stack
            direction="row"
            spacing={1}
            alignItems="flex-start"
            sx={{
                py: 0.6,
            }}
        >
            <ShieldRounded
                sx={{
                    color: "#60a5fa",
                    fontSize: 18,
                    mt: 0.2,
                }}
            />

            <Box>
                <Typography
                    sx={{
                        fontWeight: 650,
                        fontSize: 13,
                    }}
                >
                    {
                        friendlyActionName(
                            rawName,
                        )
                    }
                </Typography>

                <Typography
                    sx={{
                        color: "#94a3b8",
                        fontSize: 11,
                    }}
                >
                    Virtual action only.
                    No endpoint change is executed.
                </Typography>
            </Box>
        </Stack>
    );
}


// ============================================================
// PLAN RISK RESULT
// ============================================================

function RiskResult({
    plan,
    baseline,
}) {
    return (
        <Box
            sx={{
                minWidth: 245,
                p: 2.5,
                borderRadius: "14px",
                bgcolor: "#0f172a",
                border: "1px solid #1e293b",
            }}
        >
            <Typography
                sx={{
                    color: "#94a3b8",
                    fontSize: 12,
                }}
            >
                Modeled heuristic risk
            </Typography>

            <Stack
                direction="row"
                alignItems="center"
                justifyContent="space-between"
                sx={{
                    my: 2,
                }}
            >
                <Box>
                    <Typography
                        color="text.secondary"
                        fontSize={11}
                    >
                        Before
                    </Typography>

                    <Typography
                        fontSize={30}
                        fontWeight={800}
                        color="#f87171"
                    >
                        {
                            display(
                                plan.before
                                ??
                                baseline,
                            )
                        }
                    </Typography>
                </Box>

                <ArrowForwardRounded
                    sx={{
                        color:
                            "#64748b",
                    }}
                />

                <Box>
                    <Typography
                        color="text.secondary"
                        fontSize={11}
                    >
                        Virtual after
                    </Typography>

                    <Typography
                        fontSize={30}
                        fontWeight={800}
                        color="#4ade80"
                    >
                        {
                            display(
                                plan.after,
                            )
                        }
                    </Typography>
                </Box>
            </Stack>

            <Divider
                sx={{
                    my: 1.5,
                }}
            />

            <ResultRow
                label="Modeled reduction"
                value={
                    plan.reduction ===
                    null
                        ? "Not reported"
                        : `${plan.reduction}%`
                }
            />

            <ResultRow
                label="Operational impact"
                value={
                    plan.impact
                }
            />

            <ResultRow
                label="Ranking score"
                value={
                    plan.score
                }
            />

            <Typography
                sx={{
                    mt: 2,
                    color: "#fbbf24",
                    fontSize: 11,
                }}
            >
                A zero virtual residual score does not prove
                that a real threat was eliminated.
            </Typography>
        </Box>
    );
}


// ============================================================
// ALTERNATIVE PLAN
// ============================================================

function AlternativePlan({
    plan,
    onView,
}) {
    const color =
        impactColor(
            plan.impact,
        );

    return (
        <Card
            sx={{
                height: "100%",
            }}
        >
            <CardContent
                sx={{
                    p: 2.5,
                }}
            >
                <Stack
                    direction="row"
                    justifyContent="space-between"
                    alignItems="center"
                    sx={{
                        mb: 2,
                    }}
                >
                    <Box
                        sx={{
                            height: 44,
                            width: 44,
                            borderRadius: "12px",
                            display: "grid",
                            placeItems: "center",
                            bgcolor:
                                "rgba(59,130,246,0.12)",
                            color: "#60a5fa",
                        }}
                    >
                        {
                            plan.impact ===
                            "HIGH"
                                ? (
                                    <DevicesRounded />
                                )
                                : (
                                    <ScienceRounded />
                                )
                        }
                    </Box>

                    <Chip
                        size="small"
                        label={
                            plan.impact
                        }
                        sx={{
                            color,
                            bgcolor:
                                `${color}15`,
                        }}
                    />
                </Stack>

                <Typography
                    fontWeight={750}
                >
                    {plan.title}
                </Typography>

                <Typography
                    sx={{
                        color: "#94a3b8",
                        mt: 1,
                        minHeight: 55,
                        fontSize: 12,
                    }}
                >
                    {plan.description}
                </Typography>

                <Box
                    sx={{
                        bgcolor: "#0f172a",
                        borderRadius: 2,
                        p: 2,
                        mt: 2,
                    }}
                >
                    <ResultRow
                        label="Baseline"
                        value={
                            plan.before
                        }
                    />

                    <ResultRow
                        label="Residual"
                        value={
                            plan.after
                        }
                    />

                    <ResultRow
                        label="Ranking"
                        value={
                            plan.score
                        }
                    />

                    <ResultRow
                        label="Virtual failures"
                        value={
                            plan.failures.length
                        }
                    />
                </Box>

                <Button
                    fullWidth
                    variant="outlined"
                    sx={{
                        mt: 2,
                    }}
                    onClick={
                        () =>
                            onView(
                                plan,
                            )
                    }
                >
                    View Simulation
                </Button>
            </CardContent>
        </Card>
    );
}


// ============================================================
// DIGITAL TWIN GRAPH
// ============================================================

function DigitalTwinGraph({
    activeType,
    succeeded,
    state,
}) {
    const safeState =
        object(state);

    const nodes = [
        {
            id: "process",
            name: "PROCESSES",
            x: 48,
            y: 27,
        },
        {
            id: "network",
            name: "NETWORK",
            x: 463,
            y: 27,
        },
        {
            id: "file",
            name: "FILES",
            x: 48,
            y: 183,
        },
        {
            id: "registry",
            name: "REGISTRY",
            x: 463,
            y: 183,
        },
    ];

    const lines = [
        "M255 120 L156 71",
        "M365 120 L463 71",
        "M255 166 L156 203",
        "M365 166 L463 203",
    ];

    return (
        <svg
            viewBox="0 0 620 260"
            style={{
                width: "100%",
                maxHeight: 290,
            }}
            role="img"
            aria-label="Virtual endpoint state diagram"
        >
            <g
                stroke="#3b82f6"
                strokeWidth="2"
                strokeDasharray="6 6"
                opacity="0.60"
            >
                {
                    lines.map(
                        (
                            line,
                            index,
                        ) => (
                            <path
                                key={index}
                                d={line}
                            />
                        ),
                    )
                }
            </g>

            <rect
                x="249"
                y="102"
                width="122"
                height="76"
                rx="14"
                fill={
                    safeState
                        .endpoint_isolated
                        ? "#4a2e22"
                        : "#193454"
                }
                stroke={
                    safeState
                        .endpoint_isolated
                        ? "#f59e0b"
                        : "#60a5fa"
                }
                strokeWidth="2"
            />

            <text
                x="310"
                y="131"
                fontSize="12"
                textAnchor="middle"
                fill="#dbeafe"
            >
                ENDPOINT
            </text>

            <text
                x="310"
                y="150"
                fontSize="10"
                textAnchor="middle"
                fill="#93c5fd"
            >
                {
                    safeState
                        .endpoint_isolated
                        ? "VIRTUALLY ISOLATED"
                        : "DIGITAL TWIN"
                }
            </text>

            {
                nodes.map(
                    (
                        node,
                    ) => {
                        const active =
                            activeType ===
                            node.id;

                        const border =
                            active
                                ? (
                                    succeeded
                                        ? "#22c55e"
                                        : "#f59e0b"
                                )
                                : "#64748b";

                        return (
                            <g
                                key={
                                    node.id
                                }
                            >
                                <rect
                                    x={
                                        node.x
                                    }
                                    y={
                                        node.y
                                    }
                                    width="110"
                                    height="48"
                                    rx="10"
                                    fill={
                                        active
                                            ? "#17372f"
                                            : "#16243a"
                                    }
                                    stroke={
                                        border
                                    }
                                    strokeWidth={
                                        active
                                            ? 2.5
                                            : 1.2
                                    }
                                />

                                <text
                                    x={
                                        node.x +
                                        55
                                    }
                                    y={
                                        node.y +
                                        28
                                    }
                                    fontSize="11"
                                    textAnchor="middle"
                                    fill="#e2e8f0"
                                >
                                    {
                                        node.name
                                    }
                                </text>
                            </g>
                        );
                    },
                )
            }
        </svg>
    );
}


// ============================================================
// DIGITAL TWIN PLAYER
// ============================================================

function AnimationPlayer({
    plan,
    onClose,
}) {
    const [
        position,
        setPosition,
    ] =
        useState(0);

    const [
        playing,
        setPlaying,
    ] =
        useState(false);

    const frames =
        useMemo(
            () => {
                if (!plan) {
                    return [];
                }

                if (
                    plan.playback.length
                ) {
                    return plan.playback;
                }

                return [
                    {
                        step: 0,
                        action_type:
                            "BASELINE",
                        status:
                            "RECORDED_BASELINE",
                        success:
                            true,
                        risk_score:
                            plan.before,
                        risk_components:
                            plan.baselineComponents,
                        state:
                            null,
                    },

                    ...plan.actionResults.map(
                        (
                            item,
                            index,
                        ) => ({
                            step:
                                index +
                                1,

                            action_type:
                                item.action_type,

                            status:
                                object(
                                    item.result,
                                ).status
                                ||
                                "UNKNOWN",

                            success:
                                object(
                                    item.result,
                                ).success ===
                                true,

                            risk_score:
                                index ===
                                plan
                                    .actionResults
                                    .length -
                                    1
                                    ? plan.after
                                    : null,

                            risk_components:
                                index ===
                                plan
                                    .actionResults
                                    .length -
                                    1
                                    ? plan
                                        .residualComponents
                                    : {},

                            state:
                                null,
                        }),
                    ),
                ];
            },
            [
                plan,
            ],
        );

    useEffect(
        () => {
            setPosition(0);
            setPlaying(false);
        },
        [
            plan,
        ],
    );

    useEffect(
        () => {
            if (
                !playing
                ||
                frames.length <
                2
            ) {
                return undefined;
            }

            const timer =
                window.setInterval(
                    () => {
                        setPosition(
                            (
                                current,
                            ) => {
                                if (
                                    current >=
                                    frames.length -
                                    1
                                ) {
                                    setPlaying(
                                        false,
                                    );

                                    return current;
                                }

                                return (
                                    current +
                                    1
                                );
                            },
                        );
                    },
                    1350,
                );

            return (
                () => {
                    window.clearInterval(
                        timer,
                    );
                }
            );
        },
        [
            playing,
            frames.length,
        ],
    );

    if (!plan) {
        return null;
    }

    const current =
        frames[
            Math.min(
                position,
                Math.max(
                    0,
                    frames.length -
                    1,
                ),
            )
        ]
        ||
        {};

    const state =
        object(
            current.state,
        );

    const components =
        object(
            current.risk_components,
        );

    const action =
        String(
            current.action_type
            ||
            "BASELINE",
        ).toUpperCase();

    const activeType =
        action.includes(
            "PROCESS",
        )
            ? "process"
            : action.includes(
                "FILE",
            )
                ? "file"
                : (
                    action.includes(
                        "NETWORK",
                    )
                    ||
                    action.includes(
                        "ISOLATE",
                    )
                )
                    ? "network"
                    : action.includes(
                        "PERSISTENCE",
                    )
                        ? "registry"
                        : "baseline";

    const last =
        position >=
        frames.length - 1;

    const succeeded =
        current.success === true;

    return (
        <Dialog
            open={
                Boolean(
                    plan,
                )
            }
            onClose={
                onClose
            }
            fullWidth
            maxWidth="lg"
            PaperProps={{
                sx: {
                    bgcolor:
                        "#0b1424",

                    backgroundImage:
                        "none",

                    border:
                        "1px solid #334155",
                },
            }}
        >
            <DialogTitle>
                <Stack
                    direction="row"
                    justifyContent="space-between"
                    alignItems="center"
                    spacing={2}
                >
                    <Box>
                        <Typography
                            fontWeight={800}
                            fontSize={18}
                        >
                            Digital Twin — {plan.title}
                        </Typography>

                        <Typography
                            color="text.secondary"
                            fontSize={12}
                        >
                            Read-only virtual playback
                        </Typography>
                    </Box>

                    <Chip
                        size="small"
                        label="SIMULATION ONLY"
                        color="info"
                    />
                </Stack>
            </DialogTitle>

            <DialogContent
                dividers
            >
                <Card
                    sx={{
                        bgcolor:
                            "#0f172a",

                        mb: 2,
                    }}
                >
                    <CardContent>
                        <Typography
                            sx={{
                                color:
                                    "#94a3b8",

                                fontSize:
                                    12,

                                mb: 2,
                            }}
                        >
                            Highlighted nodes indicate the active
                            virtual step. This diagram does not control
                            your computer.
                        </Typography>

                        <DigitalTwinGraph
                            activeType={
                                activeType
                            }
                            succeeded={
                                succeeded
                            }
                            state={
                                state
                            }
                        />

                        <Stack
                            direction="row"
                            justifyContent="space-between"
                            alignItems="center"
                            sx={{
                                mt: 1,
                            }}
                        >
                            <Typography
                                fontSize={12}
                            >
                                Step {position + 1}
                                {" "}
                                of
                                {" "}
                                {frames.length}
                            </Typography>

                            <Chip
                                size="small"
                                label={
                                    pretty(
                                        current.status
                                        ||
                                        "UNKNOWN",
                                    )
                                }
                                color={
                                    succeeded
                                        ? "success"
                                        : "warning"
                                }
                            />
                        </Stack>

                        <LinearProgress
                            variant="determinate"
                            value={
                                frames.length
                                    ? (
                                        (
                                            position +
                                            1
                                        )
                                        /
                                        frames.length
                                        *
                                        100
                                    )
                                    : 0
                            }
                            sx={{
                                mt: 1.5,
                                height: 8,
                                borderRadius: 3,
                            }}
                        />

                        <Stack
                            direction="row"
                            justifyContent="space-between"
                            alignItems="center"
                            sx={{
                                mt: 2,
                            }}
                        >
                            <Typography
                                fontWeight={650}
                            >
                                {
                                    friendlyActionName(
                                        action,
                                    )
                                }
                            </Typography>

                            <Typography
                                fontWeight={800}
                                fontSize={26}
                                color="#93c5fd"
                            >
                                {
                                    display(
                                        current
                                            .risk_score,
                                    )
                                }
                            </Typography>
                        </Stack>

                        <Typography
                            sx={{
                                color:
                                    "#64748b",

                                fontSize:
                                    11,
                            }}
                        >
                            Modeled heuristic risk at this step
                        </Typography>

                        {
                            state.total_processes !==
                            undefined
                                ? (
                                    <Stack
                                        direction="row"
                                        flexWrap="wrap"
                                        gap={1}
                                        sx={{
                                            mt: 2,
                                        }}
                                    >
                                        <Chip
                                            size="small"
                                            label={
                                                `Processes: ${display(
                                                    state.active_processes,
                                                )}`
                                            }
                                        />

                                        <Chip
                                            size="small"
                                            label={
                                                `Files: ${display(
                                                    state.active_files,
                                                )}`
                                            }
                                        />

                                        <Chip
                                            size="small"
                                            label={
                                                `Connections: ${display(
                                                    state.active_network_connections,
                                                )}`
                                            }
                                        />

                                        <Chip
                                            size="small"
                                            label={
                                                `Persistence: ${display(
                                                    state.active_persistence_artifacts,
                                                )}`
                                            }
                                        />

                                        <Chip
                                            size="small"
                                            color={
                                                state
                                                    .endpoint_isolated
                                                    ? "warning"
                                                    : "default"
                                            }
                                            label={
                                                state
                                                    .endpoint_isolated
                                                    ? "Virtually isolated"
                                                    : "Not isolated"
                                            }
                                        />
                                    </Stack>
                                )
                                : (
                                    <Typography
                                        sx={{
                                            color:
                                                "#94a3b8",

                                            fontSize:
                                                12,

                                            mt: 2,
                                        }}
                                    >
                                        No intermediate endpoint-state
                                        snapshot was recorded for this step.
                                    </Typography>
                                )
                        }
                    </CardContent>
                </Card>

                <Stack
                    direction="row"
                    justifyContent="center"
                    flexWrap="wrap"
                    gap={1}
                    sx={{
                        mb: 3,
                    }}
                >
                    <Button
                        variant="outlined"
                        startIcon={
                            <SkipPreviousRounded />
                        }
                        disabled={
                            position ===
                            0
                        }
                        onClick={
                            () => {
                                setPlaying(
                                    false,
                                );

                                setPosition(
                                    (
                                        currentPosition,
                                    ) =>
                                        Math.max(
                                            0,
                                            currentPosition -
                                            1,
                                        ),
                                );
                            }
                        }
                    >
                        Previous
                    </Button>

                    <Button
                        variant="contained"
                        startIcon={
                            playing
                                ? (
                                    <PauseRounded />
                                )
                                : (
                                    <PlayArrowRounded />
                                )
                        }
                        disabled={
                            frames.length <
                            2
                            ||
                            last
                        }
                        onClick={
                            () =>
                                setPlaying(
                                    (
                                        value,
                                    ) =>
                                        !value,
                                )
                        }
                    >
                        {
                            playing
                                ? "Pause"
                                : "Play"
                        }
                    </Button>

                    <Button
                        variant="outlined"
                        startIcon={
                            <SkipNextRounded />
                        }
                        disabled={
                            last
                        }
                        onClick={
                            () => {
                                setPlaying(
                                    false,
                                );

                                setPosition(
                                    (
                                        currentPosition,
                                    ) =>
                                        Math.min(
                                            frames.length -
                                            1,
                                            currentPosition +
                                            1,
                                        ),
                                );
                            }
                        }
                    >
                        Next
                    </Button>

                    <Button
                        variant="outlined"
                        startIcon={
                            <ReplayRounded />
                        }
                        onClick={
                            () => {
                                setPlaying(
                                    false,
                                );

                                setPosition(
                                    0,
                                );
                            }
                        }
                    >
                        Replay
                    </Button>
                </Stack>

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

                        gap: 2,
                    }}
                >
                    <RiskBreakdown
                        title="Risk components at this step"
                        components={
                            components
                        }
                    />

                    <Box
                        sx={{
                            p: 2.5,
                            bgcolor: "#0f172a",
                            borderRadius: "14px",
                            border:
                                "1px solid #1e293b",
                        }}
                    >
                        <Typography
                            fontWeight={700}
                        >
                            Virtual Action Outcome
                        </Typography>

                        <Divider
                            sx={{
                                my: 1.5,
                            }}
                        />

                        <ResultRow
                            label="Action"
                            value={
                                friendlyActionName(
                                    action,
                                )
                            }
                        />

                        <ResultRow
                            label="Status"
                            value={
                                pretty(
                                    current.status,
                                )
                            }
                        />

                        <ResultRow
                            label="Virtual success"
                            value={
                                current.success ===
                                true
                                    ? "Yes — cloned state only"
                                    : "No / not established"
                            }
                        />

                        <ResultRow
                            label="Plan impact"
                            value={
                                plan.impact
                            }
                        />

                        <Typography
                            sx={{
                                color:
                                    "#94a3b8",

                                mt: 2,
                                fontSize: 12,
                            }}
                        >
                            A virtual success means the simulator
                            changed its cloned representation.
                            It does not prove the same action would
                            succeed on a real endpoint.
                        </Typography>
                    </Box>
                </Box>

                {
                    !!plan.failures.length
                    &&
                    (
                        <Alert
                            severity="warning"
                            sx={{
                                mt: 2,
                            }}
                        >
                            Virtual actions with reported failures:
                            {" "}

                            {
                                plan.failures
                                    .map(
                                        pretty,
                                    )
                                    .join(
                                        ", ",
                                    )
                            }
                        </Alert>
                    )
                }

                <Alert
                    severity="info"
                    sx={{
                        mt: 2,
                    }}
                >
                    Plan ranking and modeled risk reduction
                    are heuristic. This preview never authorizes
                    or executes a real endpoint action.
                </Alert>
            </DialogContent>

            <DialogActions>
                <Button
                    onClick={
                        onClose
                    }
                >
                    Close
                </Button>
            </DialogActions>
        </Dialog>
    );
}


// ============================================================
// MAIN PAGE
// ============================================================

export default function ResponseSimulator() {
    const location =
        useLocation();

    const initialId =
        String(
            new URLSearchParams(
                location.search,
            ).get(
                "incidentId",
            )
            ||
            location.state?.incidentId
            ||
            location.state?.incident_id
            ||
            "",
        );

    const [
        incidents,
        setIncidents,
    ] =
        useState([]);

    const [
        incidentId,
        setIncidentId,
    ] =
        useState(
            initialId,
        );

    const [
        loadingList,
        setLoadingList,
    ] =
        useState(
            true,
        );

    const [
        loadingTwin,
        setLoadingTwin,
    ] =
        useState(
            false,
        );

    const [
        listError,
        setListError,
    ] =
        useState("");

    const [
        twinError,
        setTwinError,
    ] =
        useState("");

    const [
        data,
        setData,
    ] =
        useState(
            null,
        );

    const [
        viewed,
        setViewed,
    ] =
        useState(
            null,
        );

    const [
        refreshKey,
        setRefreshKey,
    ] =
        useState(0);


    // ========================================================
    // LOAD USER-VISIBLE CANONICAL INCIDENTS
    // ========================================================

    const loadList =
        useCallback(
            async () => {
                setLoadingList(
                    true,
                );

                setListError("");

                try {
                    const response =
                        await api.get(
                            "/security/incidents",
                            {
                                params: {
                                    limit:
                                        INCIDENT_LIMIT,
                                },
                            },
                        );

                    const payload =
                        response.data
                        ||
                        {};

                    if (
                        payload
                            .schema_version !==
                        "sentinelx.security.v1"
                    ) {
                        throw new Error(
                            "Unexpected canonical security contract version.",
                        );
                    }

                    const rows =
                        array(
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
                                            item.incident_id,
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
                                initialId
                                &&
                                rows.some(
                                    (
                                        item,
                                    ) =>
                                        String(
                                            item.incident_id,
                                        )
                                        ===
                                        String(
                                            initialId,
                                        ),
                                )
                            ) {
                                return initialId;
                            }

                            const preferred =
                                rows.find(
                                    (
                                        item,
                                    ) =>
                                        String(
                                            item.incident_id,
                                        )
                                        ===
                                        "SYNTH-INC-FULL-CHAIN",
                                )
                                ||
                                rows[0];

                            return preferred
                                ? String(
                                    preferred.incident_id,
                                )
                                : "";
                        },
                    );
                }
                catch (error) {
                    setIncidents([]);

                    setListError(
                        errorText(
                            error,
                        ),
                    );
                }
                finally {
                    setLoadingList(
                        false,
                    );
                }
            },
            [
                initialId,
            ],
        );


    useEffect(
        () => {
            loadList();
        },
        [
            loadList,
        ],
    );


    // ========================================================
    // LOAD CANONICAL PROTECTION PREVIEW
    // ========================================================

    useEffect(
        () => {
            let active =
                true;

            setData(
                null,
            );

            setViewed(
                null,
            );

            setTwinError("");

            if (
                !incidentId
            ) {
                setLoadingTwin(
                    false,
                );

                return (
                    () => {
                        active =
                            false;
                    }
                );
            }

            setLoadingTwin(
                true,
            );

            async function loadTwin() {
                try {
                    const result =
                        (
                            await api.get(
                                `/security/incidents/${encodeURIComponent(
                                    incidentId,
                                )}/protection-preview`,
                            )
                        ).data;

                    if (
                        !active
                    ) {
                        return;
                    }

                    if (
                        result
                            ?.incident
                            ?.incident_id
                        &&
                        String(
                            result
                                .incident
                                .incident_id,
                        )
                        !==
                        String(
                            incidentId,
                        )
                    ) {
                        throw new Error(
                            "Digital Twin incident identity mismatch.",
                        );
                    }

                    setData(
                        result,
                    );
                }
                catch (error) {
                    if (
                        active
                    ) {
                        setTwinError(
                            errorText(
                                error,
                            ),
                        );
                    }
                }
                finally {
                    if (
                        active
                    ) {
                        setLoadingTwin(
                            false,
                        );
                    }
                }
            }

            loadTwin();

            return (
                () => {
                    active =
                        false;
                }
            );
        },
        [
            incidentId,
            refreshKey,
        ],
    );


    // ========================================================
    // CANONICAL PAGE DATA
    // ========================================================

    const selectedIncident =
        useMemo(
            () =>
                incidents.find(
                    (
                        item,
                    ) =>
                        String(
                            item.incident_id,
                        )
                        ===
                        String(
                            incidentId,
                        ),
                )
                ||
                null,
            [
                incidents,
                incidentId,
            ],
        );

    const decision =
        object(data);

    const protection =
        object(
            decision.protection,
        );

    const riskContract =
        object(
            decision.risk,
        );

    const investigationRisk =
        object(
            riskContract.investigation,
        );

    const simulationRisk =
        object(
            riskContract.simulation,
        );

    const investigation =
        object(
            decision.investigation,
        );

    const baseline =
        number(
            simulationRisk.score,
        );

    const plans =
        useMemo(
            () =>
                array(
                    protection.plans,
                ).map(
                    (
                        item,
                        index,
                    ) =>
                        normalizePlan(
                            item,
                            index,
                            baseline,
                        ),
                ),
            [
                protection.plans,
                baseline,
            ],
        );

    const selectedPlanId =
        object(
            protection.best_plan,
        ).plan_id;

    const recommended =
        plans.find(
            (
                plan,
            ) =>
                plan.id ===
                selectedPlanId,
        )
        ||
        plans[0]
        ||
        null;

    const alternatives =
        plans.filter(
            (
                plan,
            ) =>
                plan.id !==
                recommended?.id,
        );

    const evidence =
        object(
            decision
                .evidence_validation,
        );

    const investigationStatus =
        String(
            investigation.status
            ||
            "UNKNOWN",
        ).toUpperCase();

    const planEligible =
        protection
            .plan_evaluation_eligible ===
        true
        &&
        plans.length > 0;

    const recordedBaselineComponents =
        object(
            simulationRisk.components,
        );

    const baselineComponents =
        Object.keys(
            recordedBaselineComponents,
        ).length
            ? recordedBaselineComponents
            : object(
                recommended
                    ?.baselineComponents,
            );

    const limitations =
        array(
            decision.limitations,
        );

    const hasData =
        Boolean(data);


    // ========================================================
    // AI STORYBOARD COMPATIBILITY ADAPTER
    // ========================================================

    const storyboardPlans =
        array(
            protection.plans,
        ).map(
            (
                plan,
            ) => ({
                plan_id:
                    plan.plan_id,

                plan_name:
                    plan.display_name
                    ||
                    plan.technical_name,

                description:
                    plan.description,

                actions:
                    array(
                        plan.actions,
                    ),

                predicted_residual_risk:
                    plan.residual_risk_score,

                risk_reduction:
                    plan.risk_reduction,

                risk_reduction_percentage:
                    plan.risk_reduction_percentage,

                plan_score:
                    plan.ranking_score,

                operational_impact:
                    plan.modeled_disruption,

                playback:
                    array(
                        plan.playback,
                    ),

                baseline_components:
                    object(
                        plan.baseline_components,
                    ),

                residual_components:
                    object(
                        plan.residual_components,
                    ),

                limitations:
                    array(
                        plan.limitations,
                    ),

                hypothetical:
                    plan.hypothetical ===
                    true,

                approval_eligible:
                    false,

                response_authorized:
                    false,

                real_endpoint_modified:
                    false,
            }),
        );

    const storyboardBestPlanId =
        object(
            protection.best_plan,
        ).plan_id;

    const storyboardBestPlan =
        storyboardPlans.find(
            (
                plan,
            ) =>
                plan.plan_id ===
                storyboardBestPlanId,
        )
        ||
        null;

    const storyboardDecision = {
        incident_id:
            decision
                ?.incident
                ?.incident_id,

        investigation_status:
            investigationStatus,

        investigation_risk_score:
            investigationRisk.score,

        initial_risk_score:
            baseline,

        baseline_risk_components:
            simulationRisk.components,

        baseline_risk_explanation:
            simulationRisk.component_explanation,

        model_type:
            simulationRisk.model_type,

        risk_semantics:
            simulationRisk.semantics,

        evidence_validation: {
            ...evidence,

            // AIStoryboard compatibility only.
            authoritative_event_count:
                evidence
                    .qualifying_event_count,
        },

        evidence_counts:
            decision.evidence_counts,

        candidate_actions:
            protection.candidate_actions,

        plans_evaluated:
            protection.plans_evaluated,

        ranked_plans:
            storyboardPlans,

        best_plan:
            storyboardBestPlan,

        decision:
            protection.decision,

        limitations:
            decision.limitations,

        preview_only:
            true,

        simulation_mode:
            true,

        real_endpoint_modified:
            false,

        approval_eligible:
            false,

        response_authorized:
            false,
    };


    // ========================================================
    // RENDER
    // ========================================================

    return (
        <Box
            sx={{
                pb: 4,
            }}
        >
            <Stack
                direction={{
                    xs: "column",
                    sm: "row",
                }}
                justifyContent="space-between"
                alignItems="flex-start"
                gap={2}
                sx={{
                    mb: 3,
                }}
            >
                <Box>
                    <Typography
                        variant="h4"
                        fontWeight={800}
                    >
                        Protection Simulator
                    </Typography>

                    <Typography
                        sx={{
                            color: "#94a3b8",
                            mt: 0.5,
                        }}
                    >
                        Evidence-aware Digital Twin visualization
                        and read-only virtual protection-plan
                        comparison.
                    </Typography>
                </Box>

                <Chip
                    icon={
                        <ShieldRounded />
                    }
                    label="SIMULATION MODE"
                    color="info"
                />
            </Stack>


            <Card
                sx={{
                    mb: 3,

                    background:
                        "linear-gradient(135deg,#131727,#111827)",

                    borderColor:
                        "rgba(59,130,246,0.30)",
                }}
            >
                <CardContent
                    sx={{
                        p: 4,
                    }}
                >
                    <Stack
                        direction="row"
                        gap={2}
                        alignItems="center"
                    >
                        <Box
                            sx={{
                                width: 64,
                                height: 64,
                                flexShrink: 0,
                                borderRadius: "18px",
                                display: "grid",
                                placeItems: "center",
                                color: "#60a5fa",
                                bgcolor:
                                    "rgba(59,130,246,0.12)",
                            }}
                        >
                            <HubRounded
                                sx={{
                                    fontSize: 38,
                                }}
                            />
                        </Box>

                        <Box>
                            <Typography
                                variant="h5"
                            >
                                Safe Protection Preview
                            </Typography>

                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    mt: 0.5,
                                }}
                            >
                                Explore hypothetical endpoint changes
                                using the current recorded incident
                                evidence. No real response is performed.
                            </Typography>
                        </Box>
                    </Stack>
                </CardContent>
            </Card>


            <Card
                sx={{
                    mb: 3,
                }}
            >
                <CardContent
                    sx={{
                        p: 3,
                    }}
                >
                    <Stack
                        direction={{
                            xs: "column",
                            md: "row",
                        }}
                        spacing={2}
                        alignItems={{
                            xs: "stretch",
                            md: "center",
                        }}
                    >
                        <FormControl
                            fullWidth
                            size="small"
                        >
                            <InputLabel
                                id="sim-incident"
                            >
                                Security incident
                            </InputLabel>

                            <Select
                                labelId="sim-incident"
                                label="Security incident"
                                value={
                                    incidentId
                                }
                                onChange={
                                    (
                                        event,
                                    ) => {
                                        setIncidentId(
                                            String(
                                                event
                                                    .target
                                                    .value,
                                            ),
                                        );
                                    }
                                }
                            >
                                {
                                    incidents.map(
                                        (
                                            incident,
                                        ) => (
                                            <MenuItem
                                                key={
                                                    incident
                                                        .incident_id
                                                }
                                                value={
                                                    String(
                                                        incident
                                                            .incident_id,
                                                    )
                                                }
                                            >
                                                {
                                                    display(
                                                        incident
                                                            .display_title
                                                        ||
                                                        incident
                                                            .title,
                                                    )
                                                }

                                                {" · "}

                                                {
                                                    display(
                                                        incident
                                                            .severity,
                                                    )
                                                }

                                                {" · "}

                                                {
                                                    display(
                                                        incident
                                                            .event_count,
                                                        "0",
                                                    )
                                                }

                                                {" event(s) — "}

                                                {
                                                    compactId(
                                                        incident
                                                            .incident_id,
                                                    )
                                                }
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
                                loadingList
                                ||
                                loadingTwin
                            }
                            onClick={
                                () => {
                                    loadList();

                                    setRefreshKey(
                                        (
                                            value,
                                        ) =>
                                            value +
                                            1,
                                    );
                                }
                            }
                        >
                            Refresh
                        </Button>
                    </Stack>

                    {
                        (
                            loadingList
                            ||
                            loadingTwin
                        )
                        &&
                        (
                            <Stack
                                direction="row"
                                spacing={1}
                                alignItems="center"
                                sx={{
                                    mt: 2,
                                }}
                            >
                                <CircularProgress
                                    size={19}
                                />

                                <Typography
                                    fontSize={12}
                                >
                                    Loading backend data...
                                </Typography>
                            </Stack>
                        )
                    }

                    {
                        listError
                        &&
                        (
                            <Alert
                                severity="warning"
                                sx={{
                                    mt: 2,
                                }}
                            >
                                {listError}
                            </Alert>
                        )
                    }

                    {
                        twinError
                        &&
                        (
                            <Alert
                                severity="error"
                                sx={{
                                    mt: 2,
                                }}
                            >
                                {twinError}
                            </Alert>
                        )
                    }

                    {
                        !loadingList
                        &&
                        incidents.length ===
                        0
                        &&
                        (
                            <Alert
                                severity="info"
                                sx={{
                                    mt: 2,
                                }}
                            >
                                No user-visible detected incidents
                                were returned.
                            </Alert>
                        )
                    }

                    {
                        hasData
                        &&
                        (
                            <Alert
                                severity="info"
                                sx={{
                                    mt: 2,
                                }}
                            >
                                Read-only Digital Twin preview.
                                No case, approval, workflow mutation
                                or real endpoint change is created.
                            </Alert>
                        )
                    }
                </CardContent>
            </Card>


            {
                !incidentId
                &&
                (
                    <Alert
                        severity="info"
                        sx={{
                            mb: 3,
                        }}
                    >
                        Select a security incident to view
                        Digital Twin diagnostics.
                    </Alert>
                )
            }


            {
                incidentId
                &&
                selectedIncident
                &&
                (
                    <Card
                        sx={{
                            mb: 3,
                            borderColor:
                                "rgba(34,197,94,0.25)",
                        }}
                    >
                        <CardContent
                            sx={{
                                p: 2.5,
                            }}
                        >
                            <Stack
                                direction={{
                                    xs: "column",
                                    md: "row",
                                }}
                                justifyContent="space-between"
                                alignItems={{
                                    xs: "flex-start",
                                    md: "center",
                                }}
                                spacing={2}
                            >
                                <Box>
                                    <Typography
                                        fontWeight={750}
                                    >
                                        Protection Preview
                                    </Typography>

                                    <Typography
                                        sx={{
                                            color:
                                                "#94a3b8",

                                            fontSize:
                                                12,

                                            mt: 0.5,
                                        }}
                                    >
                                        {
                                            display(
                                                selectedIncident
                                                    .display_title
                                                ||
                                                selectedIncident
                                                    .title,
                                            )
                                        }

                                        {" · "}

                                        {
                                            display(
                                                selectedIncident
                                                    .severity,
                                            )
                                        }

                                        {" · "}

                                        {
                                            display(
                                                selectedIncident
                                                    .event_count,
                                                "0",
                                            )
                                        }

                                        {" recorded event(s)"}
                                    </Typography>

                                    <Typography
                                        sx={{
                                            color:
                                                "#64748b",

                                            fontSize:
                                                11,

                                            mt: 0.4,
                                        }}
                                    >
                                        Incident
                                        {" "}
                                        {
                                            display(
                                                selectedIncident
                                                    .incident_id,
                                            )
                                        }
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
                                        label="VIRTUAL ONLY"
                                    />

                                    <Chip
                                        size="small"
                                        variant="outlined"
                                        label="READ-ONLY PREVIEW"
                                    />
                                </Stack>
                            </Stack>
                        </CardContent>
                    </Card>
                )
            }


            {
                hasData
                &&
                (
                    <EvidenceOverview
                        decision={
                            decision
                        }
                    />
                )
            }


            {
                hasData
                &&
                (
                    <AIStoryboard
                        incidentId={
                            incidentId
                        }
                        decision={
                            storyboardDecision
                        }
                    />
                )
            }


            {
                hasData
                &&
                (
                    <Card
                        sx={{
                            mb: 3,
                            mt: 3,
                        }}
                    >
                        <CardContent
                            sx={{
                                p: 3,
                            }}
                        >
                            <Typography
                                variant="h6"
                                sx={{
                                    mb: 2,
                                }}
                            >
                                Current Modeled Risk
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
                                                "minmax(260px,1fr) minmax(300px,1fr)",
                                        },

                                    gap: 3,
                                }}
                            >
                                <Box>
                                    <Typography
                                        sx={{
                                            color:
                                                "#64748b",

                                            fontSize:
                                                12,
                                        }}
                                    >
                                        Heuristic Digital Twin baseline
                                    </Typography>

                                    <Stack
                                        direction="row"
                                        alignItems="baseline"
                                        spacing={1}
                                        sx={{
                                            mt: 1,
                                        }}
                                    >
                                        <Typography
                                            sx={{
                                                fontSize:
                                                    48,

                                                fontWeight:
                                                    800,

                                                color:
                                                    "#f87171",
                                            }}
                                        >
                                            {
                                                display(
                                                    baseline,
                                                )
                                            }
                                        </Typography>

                                        {
                                            baseline !==
                                            null
                                            &&
                                            (
                                                <Typography
                                                    color="text.secondary"
                                                >
                                                    / 100
                                                </Typography>
                                            )
                                        }
                                    </Stack>

                                    <LinearProgress
                                        variant="determinate"
                                        value={
                                            baseline ===
                                            null
                                                ? 0
                                                : Math.max(
                                                    0,
                                                    Math.min(
                                                        baseline,
                                                        100,
                                                    ),
                                                )
                                        }
                                        sx={{
                                            height: 12,
                                            mt: 2,
                                            borderRadius: 8,
                                            bgcolor: "#1e293b",

                                            "& .MuiLinearProgress-bar":
                                                {
                                                    bgcolor:
                                                        "#ef4444",
                                                },
                                        }}
                                    />

                                    <Typography
                                        sx={{
                                            color:
                                                "#94a3b8",

                                            fontSize:
                                                12,

                                            mt: 2,
                                        }}
                                    >
                                        This score represents the simulator's
                                        heuristic components. It is not a
                                        calibrated attack probability.
                                    </Typography>

                                    <Divider
                                        sx={{
                                            my: 2,
                                        }}
                                    />

                                    <ResultRow
                                        label="Risk model"
                                        value={
                                            simulationRisk
                                                .model_type
                                            ||
                                            "Heuristic Digital Twin model"
                                        }
                                    />

                                    <ResultRow
                                        label="Plan availability"
                                        value={
                                            planEligible
                                                ? "Virtual plans available"
                                                : "No virtual plans available"
                                        }
                                    />

                                    <ResultRow
                                        label="Plans evaluated"
                                        value={
                                            plans.length
                                        }
                                    />
                                </Box>

                                <RiskBreakdown
                                    title="Baseline Risk Components"
                                    components={
                                        baselineComponents
                                    }
                                />
                            </Box>
                        </CardContent>
                    </Card>
                )
            }


            {
                hasData
                &&
                !planEligible
                &&
                (
                    <Alert
                        severity="warning"
                        icon={
                            <WarningAmberRounded />
                        }
                        sx={{
                            mb: 3,
                        }}
                    >
                        <Typography
                            fontWeight={700}
                        >
                            No virtual protection plan available
                        </Typography>

                        The current preview returned investigation
                        status
                        {" "}

                        <strong>
                            {investigationStatus}
                        </strong>
                        .

                        {" "}

                        The simulator will not invent actions when
                        no safe virtual candidate can be constructed
                        from the recorded evidence.
                    </Alert>
                )
            }


            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                Highest-Ranked Virtual Protection Plan
            </Typography>


            <Card
                sx={{
                    mb: 3,

                    borderColor:
                        "rgba(34,197,94,0.35)",

                    background:
                        "linear-gradient(135deg,#10251b,#111827)",
                }}
            >
                <CardContent
                    sx={{
                        p: 3,
                    }}
                >
                    {
                        recommended
                            ? (
                                <>
                                    <Stack
                                        direction={{
                                            xs: "column",
                                            lg: "row",
                                        }}
                                        justifyContent="space-between"
                                        spacing={3}
                                    >
                                        <Box
                                            sx={{
                                                flex: 1,
                                                minWidth: 0,
                                            }}
                                        >
                                            <Stack
                                                direction="row"
                                                gap={1}
                                                flexWrap="wrap"
                                                sx={{
                                                    mb: 1,
                                                }}
                                            >
                                                <Chip
                                                    size="small"
                                                    label="HIGHEST HEURISTIC SCORE"
                                                    color="success"
                                                />

                                                <Chip
                                                    size="small"
                                                    label={
                                                        recommended
                                                            .impact
                                                    }
                                                />

                                                <Chip
                                                    size="small"
                                                    label="VIRTUAL ONLY"
                                                    color="info"
                                                />
                                            </Stack>

                                            <Typography
                                                variant="h5"
                                            >
                                                {recommended.title}
                                            </Typography>

                                            <Typography
                                                sx={{
                                                    color:
                                                        "#94a3b8",

                                                    mt: 1,
                                                    mb: 2,
                                                }}
                                            >
                                                {recommended.description}
                                            </Typography>

                                            {
                                                recommended
                                                    .actions
                                                    .map(
                                                        (
                                                            action,
                                                            index,
                                                        ) => (
                                                            <ActionItem
                                                                key={
                                                                    `main-action-${index}`
                                                                }
                                                                action={
                                                                    action
                                                                }
                                                            />
                                                        ),
                                                    )
                                            }
                                        </Box>

                                        <RiskResult
                                            plan={
                                                recommended
                                            }
                                            baseline={
                                                baseline
                                            }
                                        />
                                    </Stack>

                                    <Divider
                                        sx={{
                                            my: 3,
                                        }}
                                    />

                                    <Stack
                                        direction={{
                                            xs: "column",
                                            sm: "row",
                                        }}
                                        justifyContent="space-between"
                                        alignItems="center"
                                        spacing={2}
                                    >
                                        <Typography
                                            sx={{
                                                color:
                                                    "#94a3b8",

                                                fontSize:
                                                    12,
                                            }}
                                        >
                                            Replay modeled state changes
                                            without executing or authorizing
                                            real actions.
                                        </Typography>

                                        <Button
                                            variant="contained"
                                            endIcon={
                                                <ArrowForwardRounded />
                                            }
                                            onClick={
                                                () =>
                                                    setViewed(
                                                        recommended,
                                                    )
                                            }
                                            sx={{
                                                bgcolor:
                                                    "#22c55e",

                                                color:
                                                    "#04120a",

                                                "&:hover":
                                                    {
                                                        bgcolor:
                                                            "#16a34a",
                                                    },
                                            }}
                                        >
                                            View Simulation
                                        </Button>
                                    </Stack>
                                </>
                            )
                            : (
                                <Alert
                                    severity="info"
                                >
                                    {
                                        !incidentId
                                            ? (
                                                "Select an incident to view "
                                                +
                                                "available simulation plans."
                                            )
                                            : loadingTwin
                                                ? (
                                                    "Loading simulation information..."
                                                )
                                                : hasData
                                                    ? (
                                                        "No eligible virtual protection "
                                                        +
                                                        "plans are available for this "
                                                        +
                                                        "incident."
                                                    )
                                                    : (
                                                        "No Digital Twin result is loaded."
                                                    )
                                    }
                                </Alert>
                            )
                    }
                </CardContent>
            </Card>


            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                Other Virtual Protection Options
            </Typography>


            {
                alternatives.length
                    ? (
                        <Box
                            sx={{
                                display:
                                    "grid",

                                gridTemplateColumns:
                                    {
                                        xs:
                                            "1fr",

                                        lg:
                                            "repeat(3,1fr)",
                                    },

                                gap: 2,
                            }}
                        >
                            {
                                alternatives.map(
                                    (
                                        plan,
                                    ) => (
                                        <AlternativePlan
                                            key={
                                                plan.id
                                            }
                                            plan={
                                                plan
                                            }
                                            onView={
                                                setViewed
                                            }
                                        />
                                    ),
                                )
                            }
                        </Box>
                    )
                    : (
                        <Card>
                            <CardContent>
                                <Alert
                                    severity="info"
                                >
                                    No other distinct virtual
                                    protection plans were evaluated
                                    for this incident.
                                </Alert>
                            </CardContent>
                        </Card>
                    )
            }


            {
                hasData
                &&
                (
                    <Card
                        sx={{
                            mt: 3,
                        }}
                    >
                        <CardContent
                            sx={{
                                p: 3,
                            }}
                        >
                            <Typography
                                variant="h6"
                                sx={{
                                    mb: 2,
                                }}
                            >
                                Model Limitations
                            </Typography>

                            {
                                limitations.length
                                    ? (
                                        limitations.map(
                                            (
                                                item,
                                                index,
                                            ) => (
                                                <Typography
                                                    key={
                                                        `limitation-${index}`
                                                    }
                                                    sx={{
                                                        color:
                                                            "#cbd5e1",

                                                        fontSize:
                                                            12,

                                                        mb: 1,
                                                    }}
                                                >
                                                    • {item}
                                                </Typography>
                                            ),
                                        )
                                    )
                                    : (
                                        <Typography
                                            sx={{
                                                color:
                                                    "#94a3b8",

                                                fontSize:
                                                    12,
                                            }}
                                        >
                                            This preview has no additional
                                            recorded model-limitations field.
                                            Do not interpret missing limitations
                                            as proof of safety.
                                        </Typography>
                                    )
                            }
                        </CardContent>
                    </Card>
                )
            }


            <Card
                sx={{
                    mt: 3,

                    borderColor:
                        "rgba(59,130,246,0.25)",
                }}
            >
                <CardContent
                    sx={{
                        display:
                            "flex",

                        gap: 2,

                        alignItems:
                            "flex-start",

                        p: 2.5,
                    }}
                >
                    <ShieldRounded
                        sx={{
                            color:
                                "#3b82f6",

                            mt: 0.2,
                        }}
                    />

                    <Box>
                        <Typography
                            fontWeight={700}
                        >
                            Simulation Mode Active
                        </Typography>

                        <Typography
                            sx={{
                                color:
                                    "#94a3b8",

                                fontSize:
                                    12,

                                mt: 0.5,
                            }}
                        >
                            Real process termination, file quarantine,
                            network blocking and endpoint isolation
                            remain disabled. Virtual outcomes must not
                            be interpreted as verified real-world
                            protection.
                        </Typography>
                    </Box>
                </CardContent>
            </Card>


            <AnimationPlayer
                plan={
                    viewed
                }
                onClose={
                    () =>
                        setViewed(
                            null,
                        )
                }
            />
        </Box>
    );
}