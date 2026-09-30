import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Grid,
    LinearProgress,
    Stack,
} from "@mui/material";

import BackendTest from "../components/BackendTest";

import {
    SecurityRounded,
    SearchRounded,
    WarningAmberRounded,
    PsychologyRounded,
    ApprovalRounded,
    CheckCircleRounded,
} from "@mui/icons-material";


function Dashboard() {

    return (

        <Box>

            {/* ================================================= */}
            {/* PAGE TITLE */}
            {/* ================================================= */}

            <Box
                sx={{
                    mb: 3,
                }}
            >

                <Typography
                    variant="h4"
                >
                    Dashboard
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt: 0.5,
                    }}
                >
                    Your Sentinel-X security overview.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* MAIN PROTECTION CARD */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb: 3,

                    background:
                        "linear-gradient(135deg, #10251b, #111827)",
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

                            justifyContent:
                                "space-between",

                            gap: 4,
                        }}
                    >

                        <Box>

                            <Box
                                sx={{
                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    gap: 1.5,

                                    mb: 1,
                                }}
                            >

                                <SecurityRounded
                                    sx={{
                                        fontSize:
                                            36,

                                        color:
                                            "#22c55e",
                                    }}
                                />


                                <Typography
                                    variant="h4"
                                >
                                    Your PC is protected
                                </Typography>

                            </Box>


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    maxWidth:
                                        600,

                                    mb: 3,
                                }}
                            >
                                Sentinel-X protection is active.
                                Your device is continuously monitored
                                for suspicious process, file, network,
                                and system activity.
                            </Typography>


                            

                        </Box>


                        {/* Protection Score */}

                        <Box
                            sx={{
                                minWidth:
                                    220,

                                textAlign:
                                    "center",
                            }}
                        >

                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    mb: 1,
                                }}
                            >
                                Protection Score
                            </Typography>


                            <Typography
                                sx={{
                                    fontSize:
                                        54,

                                    fontWeight:
                                        800,

                                    color:
                                        "#22c55e",
                                }}
                            >
                                94
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    mb: 1.5,
                                }}
                            >
                                out of 100
                            </Typography>


                            <LinearProgress
                                variant="determinate"

                                value={
                                    94
                                }

                                sx={{
                                    height:
                                        8,

                                    borderRadius:
                                        5,

                                    backgroundColor:
                                        "#1e293b",

                                    "& .MuiLinearProgress-bar":
                                    {
                                        backgroundColor:
                                            "#22c55e",
                                    },
                                }}
                            />

                        </Box>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* KPI CARDS */}
            {/* ================================================= */}

            <Grid
                container
                spacing={
                    2
                }
                sx={{
                    mb: 3,
                }}
            >

                <Grid
                    item
                    xs={12}
                    sm={6}
                    lg={3}
                >

                    <MetricCard
                        title="Active Threats"
                        value="1"
                        subtitle="Requires review"
                        icon={
                            <WarningAmberRounded />
                        }
                        status="warning"
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    lg={3}
                >

                    <MetricCard
                        title="AI Investigations"
                        value="3"
                        subtitle="Completed today"
                        icon={
                            <PsychologyRounded />
                        }
                        status="info"
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    lg={3}
                >

                    <MetricCard
                        title="Needs Approval"
                        value="2"
                        subtitle="Actions pending"
                        icon={
                            <ApprovalRounded />
                        }
                        status="warning"
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    sm={6}
                    lg={3}
                >

                    <MetricCard
                        title="Protection"
                        value="Active"
                        subtitle="All monitors running"
                        icon={
                            <CheckCircleRounded />
                        }
                        status="success"
                    />

                </Grid>

            </Grid>


            {/* ================================================= */}
            {/* RECENT ACTIVITY */}
            {/* ================================================= */}

            <Card>

                <CardContent
                    sx={{
                        p: 3,
                    }}
                >

                    <Typography
                        variant="h6"
                        sx={{
                            mb: 0.5,
                        }}
                    >
                        Recent Security Activity
                    </Typography>


                    <Typography
                        sx={{
                            color:
                                "#64748b",

                            mb: 3,

                            fontSize:
                                13,
                        }}
                    >
                        Latest activity detected by Sentinel-X.
                    </Typography>


                    <Stack
                        spacing={
                            2
                        }
                    >

                        <ActivityItem
                            icon="🔴"
                            title="Threat requires review"
                            description="Suspicious application activity was detected."
                            time="2 min ago"
                        />


                        <ActivityItem
                            icon="🤖"
                            title="AI investigation completed"
                            description="Sentinel-X completed an automated threat investigation."
                            time="8 min ago"
                        />


                        <ActivityItem
                            icon="🧪"
                            title="Response simulation completed"
                            description="The recommended protection plan was safely simulated."
                            time="15 min ago"
                        />


                        <ActivityItem
                            icon="🟢"
                            title="Protection check completed"
                            description="All active protection modules are running normally."
                            time="26 min ago"
                        />

                    </Stack>

                </CardContent>

            </Card>

        </Box>

    );

}


/* ================================================================ */
/* METRIC CARD */
/* ================================================================ */

function MetricCard({
    title,
    value,
    subtitle,
    icon,
    status,
}) {

    const colors = {
        success: "#22c55e",
        warning: "#f59e0b",
        error: "#ef4444",
        info: "#3b82f6",
    };


    const color =
        colors[
            status
        ]
        || "#94a3b8";


    return (

        <Card
            sx={{
                height:
                    "100%",
            }}
        >

            <CardContent>

                <Box
                    sx={{
                        display:
                            "flex",

                        justifyContent:
                            "space-between",

                        alignItems:
                            "flex-start",
                    }}
                >

                    <Box>

                        <Typography
                            sx={{
                                color:
                                    "#94a3b8",

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
                                fontSize:
                                    28,

                                fontWeight:
                                    700,

                                mt: 0.5,
                            }}
                        >
                            {
                                value
                            }
                        </Typography>


                        <Typography
                            sx={{
                                color:
                                    "#64748b",

                                fontSize:
                                    12,

                                mt: 0.5,
                            }}
                        >
                            {
                                subtitle
                            }
                        </Typography>

                    </Box>


                    <Box
                        sx={{
                            width:
                                42,

                            height:
                                42,

                            borderRadius:
                                "12px",

                            display:
                                "flex",

                            alignItems:
                                "center",

                            justifyContent:
                                "center",

                            color:
                                color,

                            background:
                                `${color}18`,
                        }}
                    >
                        {
                            icon
                        }
                    </Box>

                </Box>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* ACTIVITY ITEM */
/* ================================================================ */

function ActivityItem({
    icon,
    title,
    description,
    time,
}) {

    return (

        <Box
            sx={{
                display:
                    "flex",

                alignItems:
                    "center",

                justifyContent:
                    "space-between",

                gap: 2,

                p: 2,

                background:
                    "#0f172a",

                borderRadius:
                    "12px",

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

                    gap: 2,
                }}
            >

                <Box
                    sx={{
                        fontSize:
                            22,
                    }}
                >
                    {
                        icon
                    }
                </Box>


                <Box>

                    <Typography
                        sx={{
                            fontSize:
                                14,

                            fontWeight:
                                600,
                        }}
                    >
                        {
                            title
                        }
                    </Typography>


                    <Typography
                        sx={{
                            fontSize:
                                12,

                            color:
                                "#64748b",

                            mt: 0.4,
                        }}
                    >
                        {
                            description
                        }
                    </Typography>

                </Box>

            </Box>


            <Typography
                sx={{
                    color:
                        "#64748b",

                    fontSize:
                        12,

                    whiteSpace:
                        "nowrap",
                }}
            >
                {
                    time
                }
            </Typography>

        </Box>

    );

}


export default Dashboard;