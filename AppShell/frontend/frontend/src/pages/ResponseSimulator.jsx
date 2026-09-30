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
} from "@mui/material";

import {
    ScienceRounded,
    ShieldRounded,
    CheckCircleRounded,
    ArrowForwardRounded,
    WarningAmberRounded,
    DevicesRounded,
} from "@mui/icons-material";

import {
    useNavigate,
} from "react-router-dom";


const plans = [
    {
        id: "TARGETED_FULL_REMEDIATION",
        title: "Targeted Full Remediation",
        description:
            "Stops suspicious activity while limiting unnecessary impact to your device.",
        residualRisk: 0,
        reduction: 100,
        impact: "MEDIUM",
        score: 91.4,
        recommended: true,
        actions: [
            "Stop suspicious activity",
            "Quarantine suspicious files",
            "Block suspicious network activity",
            "Remove persistence mechanisms",
        ],
    },

    {
        id: "FULL_ENDPOINT_CONTAINMENT",
        title: "Full Device Containment",
        description:
            "Uses stronger containment controls to isolate the affected device.",
        residualRisk: 0,
        reduction: 100,
        impact: "HIGH",
        score: 84.4,
        recommended: false,
        actions: [
            "Isolate the device",
            "Block suspicious network activity",
            "Stop suspicious applications",
            "Restrict affected resources",
        ],
    },

    {
        id: "TARGETED_CONTAINMENT",
        title: "Targeted Containment",
        description:
            "Contains the most suspicious activity without fully isolating the device.",
        residualRisk: 12,
        reduction: 87.5,
        impact: "MEDIUM",
        score: 83.25,
        recommended: false,
        actions: [
            "Stop suspicious application",
            "Block suspicious connection",
            "Restrict suspicious file activity",
        ],
    },

    {
        id: "MINIMAL_RESPONSE",
        title: "Minimal Protection",
        description:
            "Applies only low-impact controls while preserving most normal activity.",
        residualRisk: 46,
        reduction: 52.08,
        impact: "LOW",
        score: 60.22,
        recommended: false,
        actions: [
            "Continue monitoring",
            "Block selected suspicious activity",
            "Keep the device online",
        ],
    },
];


function ResponseSimulator() {

    const navigate =
        useNavigate();

    const currentRisk =
        96;

    const recommendedPlan =
        plans.find(
            (plan) =>
                plan.recommended
        );


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
                    Response Simulator
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt: 0.5,
                    }}
                >
                    Sentinel-X safely compares protection
                    strategies before any action is approved.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* DIGITAL TWIN INTRO */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,

                    background:
                        "linear-gradient(135deg, #131727, #111827)",

                    borderColor:
                        "rgba(59,130,246,0.30)",
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

                            alignItems:
                                "center",

                            gap: 2,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                width:
                                    64,

                                height:
                                    64,

                                borderRadius:
                                    "18px",

                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                justifyContent:
                                    "center",

                                color:
                                    "#3b82f6",

                                background:
                                    "rgba(59,130,246,0.12)",
                            }}
                        >

                            <ScienceRounded
                                sx={{
                                    fontSize:
                                        38,
                                }}
                            />

                        </Box>


                        <Box>

                            <Typography
                                variant="h5"
                            >
                                Safe Response Simulation
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    mt:
                                        0.5,

                                    maxWidth:
                                        720,
                                }}
                            >
                                Sentinel-X has simulated multiple
                                response strategies using its
                                Digital Twin. No real changes were
                                made to your device.
                            </Typography>

                        </Box>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* CURRENT RISK */}
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
                                        "#64748b",

                                    fontSize:
                                        13,
                                }}
                            >
                                Current Threat Risk
                            </Typography>


                            <Box
                                sx={{
                                    display:
                                        "flex",

                                    alignItems:
                                        "baseline",

                                    gap:
                                        1,

                                    mt:
                                        0.5,
                                }}
                            >

                                <Typography
                                    sx={{
                                        fontSize:
                                            48,

                                        fontWeight:
                                            800,

                                        color:
                                            "#ef4444",
                                    }}
                                >
                                    {
                                        currentRisk
                                    }
                                </Typography>


                                <Typography
                                    sx={{
                                        color:
                                            "#64748b",
                                    }}
                                >
                                    / 100
                                </Typography>

                            </Box>

                        </Box>


                        <Box
                            sx={{
                                flex:
                                    1,

                                minWidth:
                                    260,

                                maxWidth:
                                    600,
                            }}
                        >

                            <LinearProgress
                                variant="determinate"

                                value={
                                    currentRisk
                                }

                                sx={{
                                    height:
                                        12,

                                    borderRadius:
                                        10,

                                    background:
                                        "#1e293b",

                                    "& .MuiLinearProgress-bar":
                                    {
                                        background:
                                            "#ef4444",
                                    },
                                }}
                            />


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    fontSize:
                                        13,

                                    mt:
                                        1,
                                }}
                            >
                                Sentinel-X considers this threat
                                critical and recommends reviewing
                                a protection response.
                            </Typography>

                        </Box>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* RECOMMENDED PLAN */}
            {/* ================================================= */}

            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                Recommended Protection Plan
            </Typography>


            <Card
                sx={{
                    mb: 3,

                    borderColor:
                        "rgba(34,197,94,0.40)",

                    background:
                        "linear-gradient(135deg, #10251b, #111827)",
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
                                "flex-start",

                            gap: 3,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                flex:
                                    1,

                                minWidth:
                                    300,
                            }}
                        >

                            <Box
                                sx={{
                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    gap:
                                        1,

                                    mb:
                                        1,
                                }}
                            >

                                <Chip
                                    label="RECOMMENDED"

                                    size="small"

                                    sx={{
                                        color:
                                            "#22c55e",

                                        background:
                                            "rgba(34,197,94,0.12)",

                                        fontWeight:
                                            700,
                                    }}
                                />


                                <Chip
                                    label={
                                        recommendedPlan.impact
                                    }

                                    size="small"

                                    sx={{
                                        color:
                                            "#f59e0b",

                                        background:
                                            "rgba(245,158,11,0.10)",
                                    }}
                                />

                            </Box>


                            <Typography
                                variant="h5"
                            >
                                {
                                    recommendedPlan.title
                                }
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    mt:
                                        1,

                                    maxWidth:
                                        650,
                                }}
                            >
                                {
                                    recommendedPlan.description
                                }
                            </Typography>


                            <Stack
                                spacing={
                                    1
                                }
                                sx={{
                                    mt:
                                        2,
                                }}
                            >

                                {
                                    recommendedPlan.actions.map(
                                        (
                                            action,
                                        ) => (

                                            <ActionItem
                                                key={
                                                    action
                                                }

                                                text={
                                                    action
                                                }
                                            />

                                        )
                                    )
                                }

                            </Stack>

                        </Box>


                        <RiskResult
                            currentRisk={
                                currentRisk
                            }

                            plan={
                                recommendedPlan
                            }
                        />

                    </Box>


                    <Divider
                        sx={{
                            my:
                                3,

                            borderColor:
                                "#1e293b",
                        }}
                    />


                    <Box
                        sx={{
                            display:
                                "flex",

                            justifyContent:
                                "space-between",

                            alignItems:
                                "center",

                            gap:
                                2,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box>

                            <Typography
                                sx={{
                                    fontWeight:
                                        600,
                                }}
                            >
                                Ready to review this recommendation?
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        13,

                                    mt:
                                        0.4,
                                }}
                            >
                                Important actions will still require
                                your approval.
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
                                        "/approvals"
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
                            Review & Approve
                        </Button>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* ALTERNATIVES */}
            {/* ================================================= */}

            <Typography
                variant="h6"
                sx={{
                    mb:
                        2,
                }}
            >
                Other Simulated Options
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
                                "repeat(3, 1fr)",
                        },

                    gap:
                        2,
                }}
            >

                {
                    plans
                    .filter(
                        (
                            plan,
                        ) =>
                            !plan.recommended
                    )
                    .map(
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

                                currentRisk={
                                    currentRisk
                                }
                            />

                        )
                    )
                }

            </Box>


            {/* ================================================= */}
            {/* SAFETY MESSAGE */}
            {/* ================================================= */}

            <Card
                sx={{
                    mt:
                        3,

                    borderColor:
                        "rgba(59,130,246,0.25)",
                }}
            >

                <CardContent
                    sx={{
                        display:
                            "flex",

                        alignItems:
                            "center",

                        gap:
                            2,

                        p:
                            2.5,
                    }}
                >

                    <ShieldRounded
                        sx={{
                            color:
                                "#3b82f6",
                        }}
                    />


                    <Box>

                        <Typography
                            sx={{
                                fontWeight:
                                    600,
                            }}
                        >
                            Simulation Mode
                        </Typography>


                        <Typography
                            sx={{
                                color:
                                    "#64748b",

                                fontSize:
                                    13,

                                mt:
                                    0.3,
                            }}
                        >
                            Sentinel-X has not terminated
                            processes, blocked network traffic,
                            quarantined files, or isolated your
                            device.
                        </Typography>

                    </Box>

                </CardContent>

            </Card>

        </Box>

    );

}


/* ================================================================ */
/* ACTION ITEM */
/* ================================================================ */

function ActionItem({
    text,
}) {

    return (

        <Box
            sx={{
                display:
                    "flex",

                alignItems:
                    "center",

                gap:
                    1,
            }}
        >

            <CheckCircleRounded
                sx={{
                    color:
                        "#22c55e",

                    fontSize:
                        18,
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
/* RISK RESULT */
/* ================================================================ */

function RiskResult({
    currentRisk,
    plan,
}) {

    return (

        <Box
            sx={{
                minWidth:
                    250,

                p:
                    2.5,

                borderRadius:
                    "14px",

                background:
                    "#0f172a",

                border:
                    "1px solid #1e293b",
            }}
        >

            <Typography
                sx={{
                    color:
                        "#64748b",

                    fontSize:
                        12,
                }}
            >
                Predicted Risk
            </Typography>


            <Box
                sx={{
                    display:
                        "flex",

                    justifyContent:
                        "space-between",

                    alignItems:
                        "center",

                    mt:
                        1.5,
                }}
            >

                <Box>

                    <Typography
                        sx={{
                            color:
                                "#64748b",

                            fontSize:
                                11,
                        }}
                    >
                        Before
                    </Typography>


                    <Typography
                        sx={{
                            fontSize:
                                30,

                            fontWeight:
                                800,

                            color:
                                "#ef4444",
                        }}
                    >
                        {
                            currentRisk
                        }
                    </Typography>

                </Box>


                <Typography
                    sx={{
                        color:
                            "#64748b",

                        fontSize:
                            24,
                    }}
                >
                    →
                </Typography>


                <Box>

                    <Typography
                        sx={{
                            color:
                                "#64748b",

                            fontSize:
                                11,
                        }}
                    >
                        After
                    </Typography>


                    <Typography
                        sx={{
                            fontSize:
                                30,

                            fontWeight:
                                800,

                            color:
                                "#22c55e",
                        }}
                    >
                        {
                            plan.residualRisk
                        }
                    </Typography>

                </Box>

            </Box>


            <Divider
                sx={{
                    my:
                        2,

                    borderColor:
                        "#1e293b",
                }}
            />


            <ResultRow
                label="Risk reduction"
                value={
                    `${plan.reduction}%`
                }
            />

            <ResultRow
                label="System impact"
                value={
                    plan.impact
                }
            />

            <ResultRow
                label="Plan score"
                value={
                    plan.score
                }
            />

        </Box>

    );

}


/* ================================================================ */
/* ALTERNATIVE PLAN */
/* ================================================================ */

function AlternativePlan({
    plan,
    currentRisk,
}) {

    const impactColor =
        getImpactColor(
            plan.impact
        );


    return (

        <Card
            sx={{
                height:
                    "100%",
            }}
        >

            <CardContent
                sx={{
                    p:
                        2.5,
                }}
            >

                <Box
                    sx={{
                        display:
                            "flex",

                        justifyContent:
                            "space-between",

                        alignItems:
                            "flex-start",

                        gap:
                            1,

                        mb:
                            1.5,
                    }}
                >

                    <Box
                        sx={{
                            width:
                                42,

                            height:
                                42,

                            display:
                                "flex",

                            alignItems:
                                "center",

                            justifyContent:
                                "center",

                            borderRadius:
                                "12px",

                            color:
                                "#3b82f6",

                            background:
                                "rgba(59,130,246,0.10)",
                        }}
                    >

                        {
                            plan.impact
                            === "HIGH"
                                ? <DevicesRounded />
                                : <ScienceRounded />
                        }

                    </Box>


                    <Chip
                        label={
                            plan.impact
                        }

                        size="small"

                        sx={{
                            color:
                                impactColor,

                            background:
                                `${impactColor}15`,
                        }}
                    />

                </Box>


                <Typography
                    sx={{
                        fontWeight:
                            700,

                        fontSize:
                            16,
                    }}
                >
                    {
                        plan.title
                    }
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#64748b",

                        fontSize:
                            12,

                        lineHeight:
                            1.6,

                        mt:
                            0.8,

                        minHeight:
                            58,
                    }}
                >
                    {
                        plan.description
                    }
                </Typography>


                <Box
                    sx={{
                        mt:
                            2,

                        p:
                            2,

                        borderRadius:
                            "12px",

                        background:
                            "#0f172a",
                    }}
                >

                    <ResultRow
                        label="Risk before"
                        value={
                            currentRisk
                        }
                    />

                    <ResultRow
                        label="Risk after"
                        value={
                            plan.residualRisk
                        }
                    />

                    <ResultRow
                        label="Reduction"
                        value={
                            `${plan.reduction}%`
                        }
                    />

                </Box>


                <Button
                    variant="outlined"

                    fullWidth

                    sx={{
                        mt:
                            2,
                    }}
                >
                    View Simulation
                </Button>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* RESULT ROW */
/* ================================================================ */

function ResultRow({
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

                gap:
                    2,

                py:
                    0.5,
            }}
        >

            <Typography
                sx={{
                    color:
                        "#64748b",

                    fontSize:
                        12,
                }}
            >
                {
                    label
                }
            </Typography>


            <Typography
                sx={{
                    fontWeight:
                        700,

                    fontSize:
                        12,
                }}
            >
                {
                    value
                }
            </Typography>

        </Box>

    );

}


/* ================================================================ */
/* IMPACT COLOR */
/* ================================================================ */

function getImpactColor(
    impact
) {

    switch (
        impact
    ) {

        case "HIGH":
            return "#ef4444";

        case "MEDIUM":
            return "#f59e0b";

        case "LOW":
            return "#22c55e";

        default:
            return "#94a3b8";

    }

}


export default ResponseSimulator;