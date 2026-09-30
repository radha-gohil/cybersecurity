import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Chip,
    Stack,
    Tabs,
    Tab,
    LinearProgress,
} from "@mui/material";

import {
    WarningAmberRounded,
    ShieldRounded,
    PsychologyRounded,
    AccessTimeRounded,
    DevicesRounded,
    ArrowForwardRounded,
} from "@mui/icons-material";

import {
    useMemo,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";


const demoThreats = [
    {
        id: "THREAT-001",
        title: "Suspicious application behavior",
        description:
            "Sentinel-X detected several unusual actions from an application on your device.",
        severity: "CRITICAL",
        status: "ACTIVE",
        riskScore: 96,
        confidence: 97,
        device: "Personal Laptop",
        detectedAt: "2 minutes ago",
        category: "Application Behavior",
    },
    {
        id: "THREAT-002",
        title: "Unusual network communication",
        description:
            "An application connected to an external address that requires investigation.",
        severity: "HIGH",
        status: "INVESTIGATING",
        riskScore: 82,
        confidence: 89,
        device: "Personal Laptop",
        detectedAt: "18 minutes ago",
        category: "Network Activity",
    },
    {
        id: "THREAT-003",
        title: "Suspicious file activity",
        description:
            "A file performed behavior that Sentinel-X identified as potentially unsafe.",
        severity: "MEDIUM",
        status: "RESOLVED",
        riskScore: 58,
        confidence: 74,
        device: "Personal Laptop",
        detectedAt: "Yesterday",
        category: "File Activity",
    },
];


function Threats() {

    const navigate =
        useNavigate();

    const [filter, setFilter] =
        useState("ALL");


    const filteredThreats =
        useMemo(
            () => {

                if (
                    filter === "ALL"
                ) {
                    return demoThreats;
                }


                if (
                    filter === "ACTIVE"
                ) {
                    return demoThreats.filter(
                        (threat) =>
                            threat.status
                            === "ACTIVE"
                    );
                }


                if (
                    filter === "INVESTIGATING"
                ) {
                    return demoThreats.filter(
                        (threat) =>
                            threat.status
                            === "INVESTIGATING"
                    );
                }


                if (
                    filter === "RESOLVED"
                ) {
                    return demoThreats.filter(
                        (threat) =>
                            threat.status
                            === "RESOLVED"
                    );
                }


                return demoThreats;

            },
            [
                filter,
            ]
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
                    Threats
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt: 0.5,
                    }}
                >
                    Review security threats detected
                    and investigated by Sentinel-X.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* SUMMARY */}
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
                                "repeat(3, 1fr)",
                        },

                    gap: 2,

                    mb: 3,
                }}
            >

                <SummaryCard
                    title="Active Threats"
                    value="1"
                    color="#ef4444"
                />

                <SummaryCard
                    title="Investigating"
                    value="1"
                    color="#f59e0b"
                />

                <SummaryCard
                    title="Resolved"
                    value="1"
                    color="#22c55e"
                />

            </Box>


            {/* ================================================= */}
            {/* FILTER TABS */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,
                }}
            >

                <Tabs
                    value={
                        filter
                    }

                    onChange={
                        (
                            event,
                            value,
                        ) =>
                            setFilter(
                                value
                            )
                    }

                    sx={{
                        px: 2,

                        "& .MuiTabs-indicator":
                        {
                            background:
                                "#22c55e",
                        },

                        "& .MuiTab-root":
                        {
                            textTransform:
                                "none",

                            minHeight:
                                56,
                        },

                        "& .Mui-selected":
                        {
                            color:
                                "#22c55e !important",
                        },
                    }}
                >

                    <Tab
                        value="ALL"
                        label="All"
                    />

                    <Tab
                        value="ACTIVE"
                        label="Active"
                    />

                    <Tab
                        value="INVESTIGATING"
                        label="Investigating"
                    />

                    <Tab
                        value="RESOLVED"
                        label="Resolved"
                    />

                </Tabs>

            </Card>


            {/* ================================================= */}
            {/* THREAT CARDS */}
            {/* ================================================= */}

            <Stack
                spacing={2}
            >

                {
                    filteredThreats.map(
                        (
                            threat,
                        ) => (

                            <ThreatCard
                                key={
                                    threat.id
                                }

                                threat={
                                    threat
                                }

                                onView={
                                    () =>
                                        navigate(
                                            `/threats/${threat.id}`
                                        )
                                }
                            />

                        )
                    )
                }

            </Stack>

        </Box>

    );

}


/* ================================================================ */
/* SUMMARY CARD */
/* ================================================================ */

function SummaryCard({
    title,
    value,
    color,
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
                            "#64748b",

                        fontSize:
                            13,
                    }}
                >
                    {
                        title
                    }
                </Typography>


                <Typography
                    sx={{
                        mt: 0.5,

                        fontSize:
                            30,

                        fontWeight:
                            800,

                        color:
                            color,
                    }}
                >
                    {
                        value
                    }
                </Typography>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* THREAT CARD */
/* ================================================================ */

function ThreatCard({
    threat,
    onView,
}) {

    const severityColor =
        getSeverityColor(
            threat.severity
        );


    return (

        <Card
            sx={{
                borderColor:
                    `${severityColor}45`,

                transition:
                    "0.2s",

                "&:hover":
                {
                    transform:
                        "translateY(-2px)",

                    borderColor:
                        `${severityColor}80`,
                },
            }}
        >

            <CardContent
                sx={{
                    p: 3,
                }}
            >

                {/* HEADER */}

                <Box
                    sx={{
                        display:
                            "flex",

                        justifyContent:
                            "space-between",

                        alignItems:
                            "flex-start",

                        gap: 2,

                        flexWrap:
                            "wrap",

                        mb: 2,
                    }}
                >

                    <Box
                        sx={{
                            display:
                                "flex",

                            gap: 2,
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
                                    severityColor,

                                background:
                                    `${severityColor}15`,
                            }}
                        >

                            <WarningAmberRounded />

                        </Box>


                        <Box>

                            <Box
                                sx={{
                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    gap: 1,

                                    flexWrap:
                                        "wrap",
                                }}
                            >

                                <Typography
                                    sx={{
                                        fontSize:
                                            18,

                                        fontWeight:
                                            700,
                                    }}
                                >
                                    {
                                        threat.title
                                    }
                                </Typography>


                                <Chip
                                    label={
                                        threat.severity
                                    }

                                    size="small"

                                    sx={{
                                        color:
                                            severityColor,

                                        background:
                                            `${severityColor}15`,

                                        border:
                                            `1px solid ${severityColor}35`,

                                        fontWeight:
                                            700,
                                    }}
                                />

                            </Box>


                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        13,

                                    mt: 0.8,

                                    maxWidth:
                                        750,
                                }}
                            >
                                {
                                    threat.description
                                }
                            </Typography>

                        </Box>

                    </Box>


                    <StatusChip
                        status={
                            threat.status
                        }
                    />

                </Box>


                {/* INFO */}

                <Box
                    sx={{
                        display:
                            "grid",

                        gridTemplateColumns:
                            {
                                xs:
                                    "1fr",

                                md:
                                    "repeat(3, 1fr)",
                            },

                        gap: 2,

                        mb: 3,
                    }}
                >

                    <InfoItem
                        icon={
                            <ShieldRounded />
                        }
                        label="Risk Score"
                        value={
                            `${threat.riskScore}/100`
                        }
                    />

                    <InfoItem
                        icon={
                            <DevicesRounded />
                        }
                        label="Device"
                        value={
                            threat.device
                        }
                    />

                    <InfoItem
                        icon={
                            <AccessTimeRounded />
                        }
                        label="Detected"
                        value={
                            threat.detectedAt
                        }
                    />

                </Box>


                {/* AI CONFIDENCE */}

                <Box
                    sx={{
                        mb: 3,
                    }}
                >

                    <Box
                        sx={{
                            display:
                                "flex",

                            alignItems:
                                "center",

                            justifyContent:
                                "space-between",

                            mb: 1,
                        }}
                    >

                        <Box
                            sx={{
                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                gap: 1,
                            }}
                        >

                            <PsychologyRounded
                                sx={{
                                    color:
                                        "#8b5cf6",

                                    fontSize:
                                        19,
                                }}
                            />


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    fontSize:
                                        13,
                                }}
                            >
                                AI Confidence
                            </Typography>

                        </Box>


                        <Typography
                            sx={{
                                fontWeight:
                                    700,
                            }}
                        >
                            {
                                threat.confidence
                            }%
                        </Typography>

                    </Box>


                    <LinearProgress
                        variant="determinate"

                        value={
                            threat.confidence
                        }

                        sx={{
                            height:
                                7,

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


                {/* ACTION */}

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

                    <Typography
                        sx={{
                            color:
                                "#64748b",

                            fontSize:
                                12,
                        }}
                    >
                        {
                            threat.category
                        }
                    </Typography>


                    <Button
                        variant="outlined"

                        endIcon={
                            <ArrowForwardRounded />
                        }

                        onClick={
                            onView
                        }
                    >
                        View Threat
                    </Button>

                </Box>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* INFO ITEM */
/* ================================================================ */

function InfoItem({
    icon,
    label,
    value,
}) {

    return (

        <Box
            sx={{
                p: 2,

                borderRadius:
                    "12px",

                background:
                    "#0f172a",

                border:
                    "1px solid #1e293b",
            }}
        >

            <Box
                sx={{
                    display:
                        "flex",

                    alignItems:
                        "center",

                    gap: 1,

                    color:
                        "#64748b",

                    mb: 0.8,
                }}
            >

                {
                    icon
                }


                <Typography
                    sx={{
                        fontSize:
                            12,
                    }}
                >
                    {
                        label
                    }
                </Typography>

            </Box>


            <Typography
                sx={{
                    fontWeight:
                        600,

                    fontSize:
                        14,
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
/* STATUS CHIP */
/* ================================================================ */

function StatusChip({
    status,
}) {

    const config = {

        ACTIVE: {
            label:
                "Needs Attention",

            color:
                "#ef4444",
        },

        INVESTIGATING:
        {
            label:
                "Investigating",

            color:
                "#f59e0b",
        },

        RESOLVED:
        {
            label:
                "Resolved",

            color:
                "#22c55e",
        },

    };


    const current =
        config[
            status
        ];


    return (

        <Chip
            label={
                current.label
            }

            size="small"

            sx={{
                color:
                    current.color,

                background:
                    `${current.color}15`,

                border:
                    `1px solid ${current.color}35`,
            }}
        />

    );

}


/* ================================================================ */
/* SEVERITY COLOR */
/* ================================================================ */

function getSeverityColor(
    severity
) {

    switch (
        severity
    ) {

        case "CRITICAL":
            return "#ef4444";

        case "HIGH":
            return "#f97316";

        case "MEDIUM":
            return "#f59e0b";

        case "LOW":
            return "#3b82f6";

        default:
            return "#94a3b8";

    }

}


export default Threats;