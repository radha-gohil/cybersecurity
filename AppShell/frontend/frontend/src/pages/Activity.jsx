import {
    Box,
    Typography,
    Card,
    CardContent,
    Chip,
    Stack,
    Button,
    Divider,
} from "@mui/material";

import {
    SecurityRounded,
    SearchRounded,
    PsychologyRounded,
    ScienceRounded,
    ApprovalRounded,
    CheckCircleRounded,
    WarningAmberRounded,
    HistoryRounded,
} from "@mui/icons-material";


const activityItems = [
    {
        id: 1,
        type: "THREAT",
        title: "Threat detected",
        description:
            "Sentinel-X identified suspicious multi-stage activity on this PC.",
        time: "10:25 AM",
        status: "CRITICAL",
        icon: <WarningAmberRounded />,
    },

    {
        id: 2,
        type: "AI",
        title: "AI investigation completed",
        description:
            "The suspicious activity was analyzed and classified as critical.",
        time: "10:26 AM",
        status: "COMPLETED",
        icon: <PsychologyRounded />,
    },

    {
        id: 3,
        type: "SIMULATION",
        title: "Response simulation completed",
        description:
            "Sentinel-X simulated a protection plan and predicted risk reduction from 96 to 0.",
        time: "10:27 AM",
        status: "SIMULATED",
        icon: <ScienceRounded />,
    },

    {
        id: 4,
        type: "APPROVAL",
        title: "Protection action requires approval",
        description:
            "Important protection actions are waiting for your review.",
        time: "10:28 AM",
        status: "PENDING",
        icon: <ApprovalRounded />,
    },

    {
        id: 5,
        type: "SCAN",
        title: "Quick scan completed",
        description:
            "Sentinel-X completed a security scan of common threat locations.",
        time: "9:42 AM",
        status: "SAFE",
        icon: <SearchRounded />,
    },

    {
        id: 6,
        type: "PROTECTION",
        title: "Protection status verified",
        description:
            "Process, file, network and system monitoring are active.",
        time: "9:30 AM",
        status: "SAFE",
        icon: <SecurityRounded />,
    },
];


function Activity() {

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
                    Security Activity
                </Typography>

                <Typography
                    sx={{
                        color: "#94a3b8",
                        mt: 0.5,
                    }}
                >
                    Review recent Sentinel-X activity on this PC.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* SUMMARY */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "grid",

                    gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(3, 1fr)",
                    },

                    gap: 2,
                    mb: 3,
                }}
            >

                <SummaryCard
                    title="Security Events Today"
                    value="6"
                    color="#3b82f6"
                />

                <SummaryCard
                    title="Threats Detected"
                    value="1"
                    color="#ef4444"
                />

                <SummaryCard
                    title="Actions Waiting"
                    value="2"
                    color="#f59e0b"
                />

            </Box>


            {/* ================================================= */}
            {/* TIMELINE */}
            {/* ================================================= */}

            <Card>

                <CardContent
                    sx={{
                        p: 3,
                    }}
                >

                    <Box
                        sx={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: 2,
                            mb: 3,
                        }}
                    >

                        <Box>

                            <Typography
                                variant="h6"
                            >
                                Today
                            </Typography>

                            <Typography
                                sx={{
                                    color: "#64748b",
                                    fontSize: 13,
                                    mt: 0.3,
                                }}
                            >
                                Latest security activity on your PC.
                            </Typography>

                        </Box>


                        <Button
                            startIcon={
                                <HistoryRounded />
                            }
                            variant="outlined"
                        >
                            Refresh
                        </Button>

                    </Box>


                    <Stack
                        spacing={0}
                    >

                        {
                            activityItems.map(
                                (
                                    item,
                                    index
                                ) => (

                                    <ActivityTimelineItem
                                        key={
                                            item.id
                                        }
                                        item={
                                            item
                                        }
                                        last={
                                            index
                                            ===
                                            activityItems.length
                                            - 1
                                        }
                                    />

                                )
                            )
                        }

                    </Stack>

                </CardContent>

            </Card>

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
                        color: "#64748b",
                        fontSize: 13,
                    }}
                >
                    {title}
                </Typography>


                <Typography
                    sx={{
                        mt: 0.5,
                        fontSize: 30,
                        fontWeight: 800,
                        color: color,
                    }}
                >
                    {value}
                </Typography>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* TIMELINE ITEM */
/* ================================================================ */

function ActivityTimelineItem({
    item,
    last,
}) {

    const config =
        getActivityConfig(
            item.status
        );


    return (

        <Box
            sx={{
                display: "flex",
                gap: 2,
            }}
        >

            {/* LEFT TIMELINE */}

            <Box
                sx={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                }}
            >

                <Box
                    sx={{
                        width: 46,
                        height: 46,

                        borderRadius: "50%",

                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",

                        color:
                            config.color,

                        background:
                            `${config.color}15`,

                        border:
                            `1px solid ${config.color}35`,
                    }}
                >
                    {item.icon}
                </Box>


                {
                    !last
                    && (

                        <Box
                            sx={{
                                width: 2,
                                flex: 1,
                                minHeight: 60,
                                background: "#1e293b",
                            }}
                        />

                    )
                }

            </Box>


            {/* CONTENT */}

            <Box
                sx={{
                    flex: 1,
                    pb: last ? 0 : 3,
                }}
            >

                <Box
                    sx={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        gap: 2,
                        flexWrap: "wrap",
                    }}
                >

                    <Box>

                        <Typography
                            sx={{
                                fontWeight: 700,
                                fontSize: 16,
                            }}
                        >
                            {item.title}
                        </Typography>


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 13,
                                mt: 0.5,
                                maxWidth: 700,
                            }}
                        >
                            {item.description}
                        </Typography>

                    </Box>


                    <Box
                        sx={{
                            display: "flex",
                            alignItems: "center",
                            gap: 1,
                        }}
                    >

                        <Chip
                            label={
                                config.label
                            }
                            size="small"
                            sx={{
                                color:
                                    config.color,

                                background:
                                    `${config.color}12`,
                            }}
                        />


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 12,
                            }}
                        >
                            {item.time}
                        </Typography>

                    </Box>

                </Box>

            </Box>

        </Box>

    );

}


/* ================================================================ */
/* ACTIVITY STATUS */
/* ================================================================ */

function getActivityConfig(
    status
) {

    switch (status) {

        case "CRITICAL":
            return {
                label: "Critical",
                color: "#ef4444",
            };

        case "PENDING":
            return {
                label: "Needs Review",
                color: "#f59e0b",
            };

        case "COMPLETED":
            return {
                label: "Completed",
                color: "#8b5cf6",
            };

        case "SIMULATED":
            return {
                label: "Simulated",
                color: "#3b82f6",
            };

        case "SAFE":
            return {
                label: "Safe",
                color: "#22c55e",
            };

        default:
            return {
                label: "Info",
                color: "#94a3b8",
            };

    }

}


export default Activity;