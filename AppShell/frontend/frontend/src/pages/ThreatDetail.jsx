import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Chip,
    LinearProgress,
    Stack,
    Divider,
    Accordion,
    AccordionSummary,
    AccordionDetails,
} from "@mui/material";

import {
    ArrowBackRounded,
    WarningAmberRounded,
    PsychologyRounded,
    TimelineRounded,
    ShieldRounded,
    ScienceRounded,
    ExpandMoreRounded,
    CheckCircleRounded,
    ComputerRounded,
    InsertDriveFileRounded,
    LanguageRounded,
    SettingsRounded,
} from "@mui/icons-material";

import {
    useNavigate,
    useParams,
} from "react-router-dom";


function ThreatDetail() {

    const navigate = useNavigate();

    const { threatId } = useParams();


    // ============================================================
    // TEMPORARY FRONTEND DATA
    // Later this will come from:
    // /api/v1/incidents/{id}/full
    // ============================================================

    const threat = {
        id: threatId || "THREAT-001",

        title:
            "Suspicious Multi-Stage Activity",

        severity:
            "CRITICAL",

        riskScore:
            96,

        confidence:
            97,

        status:
            "AI Investigation Complete",

        device:
            "Personal Laptop",

        detectedAt:
            "2 minutes ago",

        summary:
            "Sentinel-X detected several suspicious activities occurring together on your device.",

        recommendedAction:
            "Targeted Full Remediation",

        residualRisk:
            0,

        systemImpact:
            "MEDIUM",
    };


    const timeline = [
        {
            icon:
                <ComputerRounded />,

            title:
                "Suspicious process started",

            description:
                "An application showed behavior that differed from normal system activity.",

            time:
                "10:24 AM",
        },

        {
            icon:
                <InsertDriveFileRounded />,

            title:
                "Unexpected file activity",

            description:
                "Sentinel-X detected suspicious file modification behavior.",

            time:
                "10:25 AM",
        },

        {
            icon:
                <LanguageRounded />,

            title:
                "External network communication",

            description:
                "The application attempted to communicate with an external network address.",

            time:
                "10:26 AM",
        },

        {
            icon:
                <SettingsRounded />,

            title:
                "Startup configuration changed",

            description:
                "A persistence-related system configuration change was detected.",

            time:
                "10:27 AM",
        },

        {
            icon:
                <PsychologyRounded />,

            title:
                "AI investigation completed",

            description:
                "Sentinel-X AI agents classified the combined activity as high-risk.",

            time:
                "10:28 AM",
        },
    ];


    return (

        <Box>

            {/* ================================================= */}
            {/* BACK */}
            {/* ================================================= */}

            <Button
                startIcon={
                    <ArrowBackRounded />
                }
                onClick={
                    () =>
                        navigate(
                            "/threats"
                        )
                }
                sx={{
                    mb: 2,
                    color: "#94a3b8",
                }}
            >
                Back to Threats
            </Button>


            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    gap: 2,
                    flexWrap: "wrap",
                    mb: 3,
                }}
            >

                <Box>

                    <Box
                        sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1.5,
                            mb: 1,
                        }}
                    >

                        <WarningAmberRounded
                            sx={{
                                color: "#ef4444",
                                fontSize: 34,
                            }}
                        />


                        <Typography
                            variant="h4"
                        >
                            {threat.title}
                        </Typography>

                    </Box>


                    <Typography
                        sx={{
                            color: "#94a3b8",
                        }}
                    >
                        {threat.summary}
                    </Typography>


                    <Stack
                        direction="row"
                        spacing={1}
                        sx={{
                            mt: 2,
                            flexWrap: "wrap",
                            rowGap: 1,
                        }}
                    >

                        <Chip
                            label={
                                threat.severity
                            }
                            sx={{
                                color: "#ef4444",
                                background:
                                    "rgba(239,68,68,0.12)",
                                fontWeight: 700,
                            }}
                        />

                        <Chip
                            label={
                                threat.status
                            }
                            sx={{
                                color: "#22c55e",
                                background:
                                    "rgba(34,197,94,0.10)",
                            }}
                        />

                        <Chip
                            label={
                                threat.device
                            }
                            variant="outlined"
                        />

                    </Stack>

                </Box>


                <Button
                    variant="contained"
                    startIcon={
                        <ShieldRounded />
                    }
                    onClick={
                        () =>
                            navigate(
                                "/response-simulator"
                            )
                    }
                    sx={{
                        background: "#22c55e",
                        color: "#04120a",

                        "&:hover": {
                            background: "#16a34a",
                        },
                    }}
                >
                    Review Recommended Action
                </Button>

            </Box>


            {/* ================================================= */}
            {/* RISK OVERVIEW */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "grid",

                    gridTemplateColumns:
                        {
                            xs: "1fr",
                            lg: "1.4fr 1fr",
                        },

                    gap: 2,

                    mb: 3,
                }}
            >

                <Card>

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
                            Threat Risk
                        </Typography>


                        <Box
                            sx={{
                                display: "flex",
                                alignItems: "baseline",
                                gap: 1,
                                mb: 1.5,
                            }}
                        >

                            <Typography
                                sx={{
                                    fontSize: 52,
                                    fontWeight: 800,
                                    color: "#ef4444",
                                }}
                            >
                                {threat.riskScore}
                            </Typography>


                            <Typography
                                sx={{
                                    color: "#64748b",
                                }}
                            >
                                / 100
                            </Typography>

                        </Box>


                        <LinearProgress
                            variant="determinate"
                            value={
                                threat.riskScore
                            }
                            sx={{
                                height: 10,
                                borderRadius: 10,
                                background: "#1e293b",

                                "& .MuiLinearProgress-bar":
                                {
                                    background:
                                        "#ef4444",
                                },
                            }}
                        />


                        <Typography
                            sx={{
                                mt: 2,
                                color: "#94a3b8",
                                fontSize: 13,
                            }}
                        >
                            This threat received a critical
                            risk assessment because several
                            suspicious behaviors occurred
                            together.
                        </Typography>

                    </CardContent>

                </Card>


                <Card>

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
                            AI Confidence
                        </Typography>


                        <Box
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                gap: 2,
                                mb: 2,
                            }}
                        >

                            <Box
                                sx={{
                                    width: 52,
                                    height: 52,
                                    borderRadius: "14px",

                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",

                                    color: "#8b5cf6",
                                    background:
                                        "rgba(139,92,246,0.12)",
                                }}
                            >

                                <PsychologyRounded />

                            </Box>


                            <Typography
                                sx={{
                                    fontSize: 38,
                                    fontWeight: 800,
                                }}
                            >
                                {threat.confidence}%
                            </Typography>

                        </Box>


                        <Typography
                            sx={{
                                color: "#94a3b8",
                                fontSize: 13,
                            }}
                        >
                            Multiple Sentinel-X detection
                            and investigation components
                            independently identified suspicious
                            activity.
                        </Typography>

                    </CardContent>

                </Card>

            </Box>


            {/* ================================================= */}
            {/* WHAT HAPPENED */}
            {/* ================================================= */}

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

                    <Box
                        sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1.2,
                            mb: 3,
                        }}
                    >

                        <TimelineRounded
                            sx={{
                                color: "#3b82f6",
                            }}
                        />


                        <Typography
                            variant="h6"
                        >
                            What Happened?
                        </Typography>

                    </Box>


                    <Stack
                        spacing={0}
                    >

                        {
                            timeline.map(
                                (
                                    event,
                                    index,
                                ) => (

                                    <TimelineItem
                                        key={
                                            event.title
                                        }
                                        {...event}
                                        last={
                                            index
                                            ===
                                            timeline.length
                                            - 1
                                        }
                                    />

                                )
                            )
                        }

                    </Stack>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* AI EXPLANATION */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,
                    borderColor:
                        "rgba(139,92,246,0.30)",
                }}
            >

                <CardContent
                    sx={{
                        p: 3,
                    }}
                >

                    <Box
                        sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1.5,
                            mb: 2,
                        }}
                    >

                        <PsychologyRounded
                            sx={{
                                color: "#8b5cf6",
                                fontSize: 30,
                            }}
                        />


                        <Box>

                            <Typography
                                variant="h6"
                            >
                                Why Sentinel-X Flagged This
                            </Typography>


                            <Typography
                                sx={{
                                    color: "#64748b",
                                    fontSize: 13,
                                }}
                            >
                                Plain-language AI explanation
                            </Typography>

                        </Box>

                    </Box>


                    <Typography
                        sx={{
                            color: "#cbd5e1",
                            mb: 2,
                            lineHeight: 1.7,
                        }}
                    >
                        Sentinel-X identified this as a serious
                        threat because several unusual activities
                        occurred close together and appear to be
                        related.
                    </Typography>


                    <Stack
                        spacing={1.2}
                    >

                        <ReasonItem
                            text="An application showed suspicious behavior."
                        />

                        <ReasonItem
                            text="Unexpected file changes were detected."
                        />

                        <ReasonItem
                            text="The application contacted an external network address."
                        />

                        <ReasonItem
                            text="A startup persistence mechanism was observed."
                        />

                    </Stack>


                    <Accordion
                        sx={{
                            mt: 2,
                            background: "#0f172a",
                            backgroundImage: "none",
                        }}
                    >

                        <AccordionSummary
                            expandIcon={
                                <ExpandMoreRounded />
                            }
                        >

                            <Typography
                                sx={{
                                    fontWeight: 600,
                                }}
                            >
                                Advanced Technical Details
                            </Typography>

                        </AccordionSummary>


                        <AccordionDetails>

                            <Typography
                                sx={{
                                    color: "#94a3b8",
                                    fontSize: 13,
                                    lineHeight: 1.8,
                                }}
                            >
                                Technical details will later show
                                Fusion-v3 evidence, behavioral AI,
                                temporal analysis, correlation data,
                                detection engine scores and related
                                security events from the Sentinel-X
                                backend.
                            </Typography>

                        </AccordionDetails>

                    </Accordion>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* RECOMMENDATION */}
            {/* ================================================= */}

            <Card
                sx={{
                    background:
                        "linear-gradient(135deg, #11241b, #111827)",
                    borderColor:
                        "rgba(34,197,94,0.30)",
                }}
            >

                <CardContent
                    sx={{
                        p: 3,
                    }}
                >

                    <Box
                        sx={{
                            display: "flex",
                            justifyContent: "space-between",
                            gap: 3,
                            flexWrap: "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                flex: 1,
                                minWidth: 260,
                            }}
                        >

                            <Typography
                                sx={{
                                    color: "#22c55e",
                                    fontSize: 12,
                                    fontWeight: 700,
                                    letterSpacing: 1,
                                    mb: 1,
                                }}
                            >
                                RECOMMENDED RESPONSE
                            </Typography>


                            <Typography
                                variant="h5"
                            >
                                {threat.recommendedAction}
                            </Typography>


                            <Typography
                                sx={{
                                    color: "#94a3b8",
                                    mt: 1,
                                    maxWidth: 620,
                                }}
                            >
                                Sentinel-X recommends this response
                                because it is predicted to reduce
                                the threat while limiting impact
                                to your device.
                            </Typography>


                            <Stack
                                spacing={1}
                                sx={{
                                    mt: 2,
                                }}
                            >

                                <ReasonItem
                                    text="Stop suspicious activity"
                                />

                                <ReasonItem
                                    text="Quarantine suspicious files"
                                />

                                <ReasonItem
                                    text="Block suspicious network activity"
                                />

                                <ReasonItem
                                    text="Remove persistence mechanisms"
                                />

                            </Stack>

                        </Box>


                        <Box
                            sx={{
                                minWidth: 230,
                            }}
                        >

                            <RiskComparison
                                before={
                                    threat.riskScore
                                }
                                after={
                                    threat.residualRisk
                                }
                            />


                            <Typography
                                sx={{
                                    mt: 2,
                                    color: "#94a3b8",
                                    fontSize: 13,
                                }}
                            >
                                System impact:
                                {" "}
                                <Box
                                    component="span"
                                    sx={{
                                        color: "#f59e0b",
                                        fontWeight: 700,
                                    }}
                                >
                                    {threat.systemImpact}
                                </Box>
                            </Typography>


                            <Button
                                fullWidth
                                variant="contained"
                                startIcon={
                                    <ScienceRounded />
                                }
                                onClick={
                                    () =>
                                        navigate(
                                            "/response-simulator"
                                        )
                                }
                                sx={{
                                    mt: 2,
                                    background: "#22c55e",
                                    color: "#04120a",

                                    "&:hover":
                                    {
                                        background: "#16a34a",
                                    },
                                }}
                            >
                                Open Response Simulator
                            </Button>

                        </Box>

                    </Box>

                </CardContent>

            </Card>

        </Box>

    );

}


/* ================================================================ */
/* TIMELINE ITEM */
/* ================================================================ */

function TimelineItem({
    icon,
    title,
    description,
    time,
    last,
}) {

    return (

        <Box
            sx={{
                display: "flex",
                gap: 2,
            }}
        >

            <Box
                sx={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                }}
            >

                <Box
                    sx={{
                        width: 42,
                        height: 42,

                        borderRadius: "50%",

                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",

                        background:
                            "rgba(59,130,246,0.10)",

                        color:
                            "#3b82f6",
                    }}
                >
                    {icon}
                </Box>


                {
                    !last
                    && (

                        <Box
                            sx={{
                                width: 2,
                                flex: 1,
                                minHeight: 45,
                                background:
                                    "#1e293b",
                            }}
                        />

                    )
                }

            </Box>


            <Box
                sx={{
                    pb: last
                        ? 0
                        : 3,

                    flex: 1,
                }}
            >

                <Box
                    sx={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 2,
                        flexWrap: "wrap",
                    }}
                >

                    <Typography
                        sx={{
                            fontWeight: 600,
                        }}
                    >
                        {title}
                    </Typography>


                    <Typography
                        sx={{
                            color: "#64748b",
                            fontSize: 12,
                        }}
                    >
                        {time}
                    </Typography>

                </Box>


                <Typography
                    sx={{
                        mt: 0.5,
                        color: "#64748b",
                        fontSize: 13,
                    }}
                >
                    {description}
                </Typography>

            </Box>

        </Box>

    );

}


/* ================================================================ */
/* REASON ITEM */
/* ================================================================ */

function ReasonItem({
    text,
}) {

    return (

        <Box
            sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
            }}
        >

            <CheckCircleRounded
                sx={{
                    color: "#22c55e",
                    fontSize: 18,
                }}
            />


            <Typography
                sx={{
                    color: "#cbd5e1",
                    fontSize: 13,
                }}
            >
                {text}
            </Typography>

        </Box>

    );

}


/* ================================================================ */
/* RISK COMPARISON */
/* ================================================================ */

function RiskComparison({
    before,
    after,
}) {

    return (

        <Box
            sx={{
                p: 2.5,

                borderRadius: "14px",

                background:
                    "#0f172a",

                border:
                    "1px solid #1e293b",
            }}
        >

            <Typography
                sx={{
                    color: "#64748b",
                    fontSize: 12,
                    mb: 1.5,
                }}
            >
                Predicted risk change
            </Typography>


            <Box
                sx={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 2,
                }}
            >

                <Box>

                    <Typography
                        sx={{
                            color: "#64748b",
                            fontSize: 11,
                        }}
                    >
                        Before
                    </Typography>

                    <Typography
                        sx={{
                            fontSize: 28,
                            fontWeight: 800,
                            color: "#ef4444",
                        }}
                    >
                        {before}
                    </Typography>

                </Box>


                <Typography
                    sx={{
                        color: "#64748b",
                        fontSize: 24,
                    }}
                >
                    →
                </Typography>


                <Box>

                    <Typography
                        sx={{
                            color: "#64748b",
                            fontSize: 11,
                        }}
                    >
                        After
                    </Typography>

                    <Typography
                        sx={{
                            fontSize: 28,
                            fontWeight: 800,
                            color: "#22c55e",
                        }}
                    >
                        {after}
                    </Typography>

                </Box>

            </Box>

        </Box>

    );

}


export default ThreatDetail;