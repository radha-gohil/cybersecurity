import {
    Box,
    Typography,
    Card,
    CardContent,
    Chip,
    Stack,
    LinearProgress,
    Button,
    Divider,
    Accordion,
    AccordionSummary,
    AccordionDetails,
} from "@mui/material";

import {
    SearchRounded,
    PsychologyRounded,
    WarningAmberRounded,
    ShieldRounded,
    CheckCircleRounded,
    ExpandMoreRounded,
    ArrowForwardRounded,
} from "@mui/icons-material";

import {
    useNavigate,
} from "react-router-dom";


function AISecurity() {

    const navigate =
        useNavigate();


    const agents = [
        {
            title:
                "Initial Threat Analysis",

            description:
                "Sentinel-X reviewed the detected activity and confirmed that it requires investigation.",

            result:
                "Threat confirmed",

            confidence:
                100,

            icon:
                <SearchRounded />,
        },

        {
            title:
                "Evidence Investigation",

            description:
                "Process, file, network, and system activity were analyzed together.",

            result:
                "Multi-stage activity identified",

            confidence:
                90,

            icon:
                <PsychologyRounded />,
        },

        {
            title:
                "Risk Assessment",

            description:
                "Sentinel-X evaluated the potential impact and likelihood of malicious behavior.",

            result:
                "Critical risk",

            confidence:
                100,

            icon:
                <WarningAmberRounded />,
        },
    ];


    return (

        <Box>

            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

            <Box
                sx={{
                    mb: 3,
                }}
            >

                <Typography
                    variant="h4"
                >
                    AI Investigation
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt: 0.5,
                    }}
                >
                    Sentinel-X AI has completed an
                    investigation of the detected threat.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* INVESTIGATION STATUS */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,

                    background:
                        "linear-gradient(135deg, #161326, #111827)",

                    borderColor:
                        "rgba(139,92,246,0.30)",
                }}
            >

                <CardContent
                    sx={{
                        p: 4,
                    }}
                >

                    <Box
                        sx={{
                            display:
                                "flex",

                            justifyContent:
                                "space-between",

                            alignItems:
                                "center",

                            gap: 2,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                display:
                                    "flex",

                                gap: 2,

                                alignItems:
                                    "center",
                            }}
                        >

                            <Box
                                sx={{
                                    width:
                                        62,

                                    height:
                                        62,

                                    borderRadius:
                                        "16px",

                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    justifyContent:
                                        "center",

                                    color:
                                        "#8b5cf6",

                                    background:
                                        "rgba(139,92,246,0.12)",
                                }}
                            >

                                <PsychologyRounded
                                    sx={{
                                        fontSize:
                                            36,
                                    }}
                                />

                            </Box>


                            <Box>

                                <Typography
                                    variant="h5"
                                >
                                    Investigation Complete
                                </Typography>


                                <Typography
                                    sx={{
                                        color:
                                            "#94a3b8",

                                        mt: 0.5,
                                    }}
                                >
                                    Multiple AI analysis stages
                                    independently identified this
                                    activity as high-risk.
                                </Typography>

                            </Box>

                        </Box>


                        <Chip
                            label="COMPLETED"

                            sx={{
                                color:
                                    "#22c55e",

                                background:
                                    "rgba(34,197,94,0.10)",

                                border:
                                    "1px solid rgba(34,197,94,0.25)",

                                fontWeight:
                                    700,
                            }}
                        />

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* AI PIPELINE */}
            {/* ================================================= */}

            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                Investigation Stages
            </Typography>


            <Stack
                spacing={0}
                sx={{
                    mb: 3,
                }}
            >

                {
                    agents.map(
                        (
                            agent,
                            index,
                        ) => (

                            <AgentStage
                                key={
                                    agent.title
                                }

                                {...agent}

                                last={
                                    index
                                    ===
                                    agents.length
                                    - 1
                                }
                            />

                        )
                    )
                }

            </Stack>


            {/* ================================================= */}
            {/* AI CONSENSUS */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,

                    borderColor:
                        "rgba(239,68,68,0.35)",
                }}
            >

                <CardContent
                    sx={{
                        p: 3,
                    }}
                >

                    <Box
                        sx={{
                            display:
                                "flex",

                            justifyContent:
                                "space-between",

                            gap: 3,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                flex: 1,
                                minWidth: 280,
                            }}
                        >

                            <Typography
                                sx={{
                                    color:
                                        "#8b5cf6",

                                    fontSize:
                                        12,

                                    fontWeight:
                                        700,

                                    letterSpacing:
                                        1,

                                    mb: 1,
                                }}
                            >
                                AI CONSENSUS
                            </Typography>


                            <Typography
                                variant="h5"
                                sx={{
                                    color:
                                        "#ef4444",
                                }}
                            >
                                Containment Recommended
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    mt: 1,

                                    maxWidth:
                                        650,
                                }}
                            >
                                Sentinel-X recommends reviewing
                                a containment response because
                                multiple suspicious behaviors
                                were observed together.
                            </Typography>

                        </Box>


                        <Box
                            sx={{
                                minWidth:
                                    230,
                            }}
                        >

                            <Box
                                sx={{
                                    display:
                                        "flex",

                                    justifyContent:
                                        "space-between",

                                    mb: 1,
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
                                    Consensus confidence
                                </Typography>


                                <Typography
                                    sx={{
                                        fontWeight:
                                            700,
                                    }}
                                >
                                    97%
                                </Typography>

                            </Box>


                            <LinearProgress
                                variant="determinate"

                                value={
                                    97
                                }

                                sx={{
                                    height:
                                        8,

                                    borderRadius:
                                        10,

                                    background:
                                        "#1e293b",

                                    "& .MuiLinearProgress-bar":
                                    {
                                        background:
                                            "#8b5cf6",
                                    },
                                }}
                            />

                        </Box>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* WHY */}
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

                    <Typography
                        variant="h6"
                        sx={{
                            mb: 2,
                        }}
                    >
                        Why Sentinel-X Reached This Conclusion
                    </Typography>


                    <Stack
                        spacing={1.3}
                    >

                        <Finding
                            text="Suspicious application behavior was detected."
                        />

                        <Finding
                            text="Unexpected file activity was observed."
                        />

                        <Finding
                            text="External network communication occurred."
                        />

                        <Finding
                            text="A persistence-related system change was identified."
                        />

                    </Stack>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* RECOMMENDATION */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,

                    background:
                        "linear-gradient(135deg, #10251b, #111827)",

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
                            display:
                                "flex",

                            justifyContent:
                                "space-between",

                            alignItems:
                                "center",

                            gap: 3,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box>

                            <Typography
                                sx={{
                                    color:
                                        "#22c55e",

                                    fontSize:
                                        12,

                                    fontWeight:
                                        700,

                                    letterSpacing:
                                        1,
                                }}
                            >
                                NEXT STEP
                            </Typography>


                            <Typography
                                variant="h6"
                                sx={{
                                    mt: 0.6,
                                }}
                            >
                                Review the recommended response
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    mt: 0.5,
                                }}
                            >
                                Sentinel-X can safely simulate
                                possible protection actions before
                                you approve anything.
                            </Typography>

                        </Box>


                        <Button
                            variant="contained"

                            endIcon={
                                <ArrowForwardRounded />
                            }

                            onClick={
                                () =>
                                    navigate(
                                        "/response-simulator"
                                    )
                            }

                            sx={{
                                background:
                                    "#22c55e",

                                color:
                                    "#04120a",

                                "&:hover":
                                {
                                    background:
                                        "#16a34a",
                                },
                            }}
                        >
                            Open Response Simulator
                        </Button>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* ADVANCED DETAILS */}
            {/* ================================================= */}

            <Accordion
                sx={{
                    background:
                        "#111827",

                    backgroundImage:
                        "none",

                    border:
                        "1px solid #1e293b",
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
                                600,
                        }}
                    >
                        Advanced AI Details
                    </Typography>

                </AccordionSummary>


                <AccordionDetails>

                    <Typography
                        sx={{
                            color:
                                "#94a3b8",

                            fontSize:
                                13,

                            mb: 2,
                        }}
                    >
                        Technical investigation information
                        will be connected to your real
                        multi-agent backend later.
                    </Typography>


                    <Divider
                        sx={{
                            borderColor:
                                "#1e293b",

                            mb: 2,
                        }}
                    />


                    <AdvancedRow
                        label="Investigation status"
                        value="COMPLETED"
                    />

                    <AdvancedRow
                        label="Risk level"
                        value="CRITICAL"
                    />

                    <AdvancedRow
                        label="Consensus"
                        value="CONTAINMENT_RECOMMENDED"
                    />

                    <AdvancedRow
                        label="Consensus confidence"
                        value="97%"
                    />

                    <AdvancedRow
                        label="Response mode"
                        value="RECOMMEND_ONLY"
                    />

                    <AdvancedRow
                        label="Autonomy level"
                        value="2"
                    />

                </AccordionDetails>

            </Accordion>

        </Box>

    );

}


/* ================================================================ */
/* AGENT STAGE */
/* ================================================================ */

function AgentStage({
    title,
    description,
    result,
    confidence,
    icon,
    last,
}) {

    return (

        <Box
            sx={{
                display:
                    "flex",

                gap: 2,
            }}
        >

            <Box
                sx={{
                    display:
                        "flex",

                    flexDirection:
                        "column",

                    alignItems:
                        "center",
                }}
            >

                <Box
                    sx={{
                        width:
                            48,

                        height:
                            48,

                        borderRadius:
                            "14px",

                        display:
                            "flex",

                        alignItems:
                            "center",

                        justifyContent:
                            "center",

                        color:
                            "#8b5cf6",

                        background:
                            "rgba(139,92,246,0.12)",

                        border:
                            "1px solid rgba(139,92,246,0.25)",
                    }}
                >
                    {
                        icon
                    }
                </Box>


                {
                    !last
                    && (

                        <Box
                            sx={{
                                width:
                                    2,

                                flex:
                                    1,

                                minHeight:
                                    45,

                                background:
                                    "#1e293b",
                            }}
                        />

                    )
                }

            </Box>


            <Card
                sx={{
                    flex:
                        1,

                    mb:
                        last
                            ? 0
                            : 2,
                }}
            >

                <CardContent
                    sx={{
                        p: 2.5,
                    }}
                >

                    <Box
                        sx={{
                            display:
                                "flex",

                            justifyContent:
                                "space-between",

                            gap: 2,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                flex:
                                    1,
                            }}
                        >

                            <Typography
                                sx={{
                                    fontWeight:
                                        700,
                                }}
                            >
                                {
                                    title
                                }
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        13,

                                    mt:
                                        0.5,
                                }}
                            >
                                {
                                    description
                                }
                            </Typography>


                            <Box
                                sx={{
                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    gap:
                                        1,

                                    mt:
                                        1.5,
                                }}
                            >

                                <CheckCircleRounded
                                    sx={{
                                        color:
                                            "#22c55e",

                                        fontSize:
                                            17,
                                    }}
                                />


                                <Typography
                                    sx={{
                                        color:
                                            "#22c55e",

                                        fontSize:
                                            13,

                                        fontWeight:
                                            600,
                                    }}
                                >
                                    {
                                        result
                                    }
                                </Typography>

                            </Box>

                        </Box>


                        <Box
                            sx={{
                                minWidth:
                                    140,
                            }}
                        >

                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        11,
                                }}
                            >
                                Confidence
                            </Typography>


                            <Typography
                                sx={{
                                    fontSize:
                                        24,

                                    fontWeight:
                                        800,

                                    mt:
                                        0.3,
                                }}
                            >
                                {
                                    confidence
                                }%
                            </Typography>

                        </Box>

                    </Box>

                </CardContent>

            </Card>

        </Box>

    );

}


/* ================================================================ */
/* FINDING */
/* ================================================================ */

function Finding({
    text,
}) {

    return (

        <Box
            sx={{
                display:
                    "flex",

                alignItems:
                    "center",

                gap: 1.2,

                p: 1.4,

                borderRadius:
                    "10px",

                background:
                    "#0f172a",
            }}
        >

            <ShieldRounded
                sx={{
                    color:
                        "#3b82f6",

                    fontSize:
                        19,
                }}
            />


            <Typography
                sx={{
                    color:
                        "#cbd5e1",

                    fontSize:
                        13,
                }}
            >
                {
                    text
                }
            </Typography>

        </Box>

    );

}


/* ================================================================ */
/* ADVANCED ROW */
/* ================================================================ */

function AdvancedRow({
    label,
    value,
}) {

    return (

        <Box
            sx={{
                display:
                    "flex",

                justifyContent:
                    "space-between",

                gap: 2,

                py: 1,
            }}
        >

            <Typography
                sx={{
                    color:
                        "#64748b",

                    fontSize:
                        13,
                }}
            >
                {
                    label
                }
            </Typography>


            <Typography
                sx={{
                    fontWeight:
                        600,

                    fontSize:
                        13,
                }}
            >
                {
                    value
                }
            </Typography>

        </Box>

    );

}


export default AISecurity;