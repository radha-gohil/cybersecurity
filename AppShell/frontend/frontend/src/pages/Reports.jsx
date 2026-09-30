import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Chip,
    Stack,
} from "@mui/material";

import {
    BarChartRounded,
    SecurityRounded,
    WarningAmberRounded,
    PsychologyRounded,
    SearchRounded,
    ApprovalRounded,
    DownloadRounded,
    CheckCircleRounded,
} from "@mui/icons-material";

import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell,
    Legend,
} from "recharts";


const protectionTrend = [
    {
        day: "Mon",
        score: 88,
    },
    {
        day: "Tue",
        score: 90,
    },
    {
        day: "Wed",
        score: 91,
    },
    {
        day: "Thu",
        score: 89,
    },
    {
        day: "Fri",
        score: 92,
    },
    {
        day: "Sat",
        score: 94,
    },
    {
        day: "Sun",
        score: 94,
    },
];


const threatCategories = [
    {
        name: "Process",
        value: 34,
    },
    {
        name: "Network",
        value: 28,
    },
    {
        name: "Files",
        value: 22,
    },
    {
        name: "System",
        value: 16,
    },
];


const COLORS = [
    "#3b82f6",
    "#8b5cf6",
    "#f59e0b",
    "#22c55e",
];


function Reports() {

    return (

        <Box>

            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 2,
                    flexWrap: "wrap",
                    mb: 3,
                }}
            >

                <Box>

                    <Typography
                        variant="h4"
                    >
                        Security Reports
                    </Typography>


                    <Typography
                        sx={{
                            color: "#94a3b8",
                            mt: 0.5,
                        }}
                    >
                        Review the recent protection activity
                        and security health of this PC.
                    </Typography>

                </Box>


                <Button
                    variant="outlined"
                    startIcon={
                        <DownloadRounded />
                    }
                >
                    Export Report
                </Button>

            </Box>


            {/* ================================================= */}
            {/* MAIN SCORE */}
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
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                            gap: 3,
                            flexWrap: "wrap",
                        }}
                    >

                        <Box>

                            <Typography
                                sx={{
                                    color: "#94a3b8",
                                    fontSize: 13,
                                }}
                            >
                                Current Protection Score
                            </Typography>


                            <Typography
                                sx={{
                                    fontSize: 58,
                                    fontWeight: 800,
                                    color: "#22c55e",
                                    lineHeight: 1.1,
                                    mt: 0.5,
                                }}
                            >
                                94
                            </Typography>


                            <Typography
                                sx={{
                                    color: "#64748b",
                                }}
                            >
                                out of 100
                            </Typography>

                        </Box>


                        <Box
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                gap: 1.2,
                            }}
                        >

                            <CheckCircleRounded
                                sx={{
                                    color: "#22c55e",
                                }}
                            />


                            <Box>

                                <Typography
                                    sx={{
                                        fontWeight: 700,
                                    }}
                                >
                                    Protection looks healthy
                                </Typography>


                                <Typography
                                    sx={{
                                        color: "#64748b",
                                        fontSize: 13,
                                        mt: 0.3,
                                    }}
                                >
                                    All primary protection modules
                                    are currently active.
                                </Typography>

                            </Box>

                        </Box>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* KPI CARDS */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "grid",

                    gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(2, 1fr)",
                        lg: "repeat(5, 1fr)",
                    },

                    gap: 2,
                    mb: 3,
                }}
            >

                <MetricCard
                    title="Threats Detected"
                    value="8"
                    icon={
                        <WarningAmberRounded />
                    }
                    color="#ef4444"
                />


                <MetricCard
                    title="Threats Resolved"
                    value="7"
                    icon={
                        <SecurityRounded />
                    }
                    color="#22c55e"
                />


                <MetricCard
                    title="AI Investigations"
                    value="12"
                    icon={
                        <PsychologyRounded />
                    }
                    color="#8b5cf6"
                />



                <MetricCard
                    title="Actions Approved"
                    value="9"
                    icon={
                        <ApprovalRounded />
                    }
                    color="#f59e0b"
                />

            </Box>


            {/* ================================================= */}
            {/* CHARTS */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "grid",

                    gridTemplateColumns: {
                        xs: "1fr",
                        lg: "1.5fr 1fr",
                    },

                    gap: 2,
                    mb: 3,
                }}
            >

                {/* PROTECTION TREND */}

                <Card>

                    <CardContent
                        sx={{
                            p: 3,
                        }}
                    >

                        <Box
                            sx={{
                                mb: 2,
                            }}
                        >

                            <Typography
                                variant="h6"
                            >
                                Protection Trend
                            </Typography>


                            <Typography
                                sx={{
                                    color: "#64748b",
                                    fontSize: 13,
                                    mt: 0.4,
                                }}
                            >
                                Security score over the last 7 days.
                            </Typography>

                        </Box>


                        <Box
                            sx={{
                                width: "100%",
                                height: 280,
                            }}
                        >

                            <ResponsiveContainer>

                                <AreaChart
                                    data={
                                        protectionTrend
                                    }
                                >

                                    <CartesianGrid
                                        strokeDasharray="3 3"
                                        stroke="#1e293b"
                                    />

                                    <XAxis
                                        dataKey="day"
                                        stroke="#64748b"
                                    />

                                    <YAxis
                                        domain={[
                                            70,
                                            100,
                                        ]}
                                        stroke="#64748b"
                                    />

                                    <Tooltip
                                        contentStyle={{
                                            background:
                                                "#0f172a",

                                            border:
                                                "1px solid #1e293b",

                                            borderRadius:
                                                "10px",
                                        }}
                                    />

                                    <Area
                                        type="monotone"
                                        dataKey="score"
                                        stroke="#22c55e"
                                        fill="#22c55e"
                                        fillOpacity={0.12}
                                        strokeWidth={3}
                                    />

                                </AreaChart>

                            </ResponsiveContainer>

                        </Box>

                    </CardContent>

                </Card>


                {/* THREAT DISTRIBUTION */}

                <Card>

                    <CardContent
                        sx={{
                            p: 3,
                        }}
                    >

                        <Typography
                            variant="h6"
                        >
                            Threat Activity
                        </Typography>


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 13,
                                mt: 0.4,
                            }}
                        >
                            Security areas involved in recent
                            detections.
                        </Typography>


                        <Box
                            sx={{
                                width: "100%",
                                height: 280,
                            }}
                        >

                            <ResponsiveContainer>

                                <PieChart>

                                    <Pie
                                        data={
                                            threatCategories
                                        }
                                        dataKey="value"
                                        nameKey="name"
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={55}
                                        outerRadius={90}
                                        paddingAngle={3}
                                    >

                                        {
                                            threatCategories.map(
                                                (
                                                    entry,
                                                    index
                                                ) => (

                                                    <Cell
                                                        key={
                                                            entry.name
                                                        }
                                                        fill={
                                                            COLORS[
                                                                index
                                                                %
                                                                COLORS.length
                                                            ]
                                                        }
                                                    />

                                                )
                                            )
                                        }

                                    </Pie>


                                    <Tooltip
                                        contentStyle={{
                                            background:
                                                "#0f172a",

                                            border:
                                                "1px solid #1e293b",

                                            borderRadius:
                                                "10px",
                                        }}
                                    />


                                    <Legend />

                                </PieChart>

                            </ResponsiveContainer>

                        </Box>

                    </CardContent>

                </Card>

            </Box>


            {/* ================================================= */}
            {/* WEEKLY SUMMARY */}
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
                        This Week
                    </Typography>


                    <Stack
                        spacing={1.5}
                    >

                        

                        <SummaryRow
                            title="Critical threats detected"
                            value="2"
                            status="Reviewed"
                        />

                        <SummaryRow
                            title="AI investigations completed"
                            value="12"
                            status="Complete"
                        />

                        <SummaryRow
                            title="Pending approvals"
                            value="1"
                            status="Needs review"
                            warning
                        />

                    </Stack>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* SECURITY SUMMARY */}
            {/* ================================================= */}

            <Card
                sx={{
                    borderColor:
                        "rgba(59,130,246,0.25)",
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
                            gap: 2,
                            alignItems: "flex-start",
                        }}
                    >

                        <BarChartRounded
                            sx={{
                                color: "#3b82f6",
                                mt: 0.3,
                            }}
                        />


                        <Box>

                            <Typography
                                sx={{
                                    fontWeight: 700,
                                }}
                            >
                                Security Summary
                            </Typography>


                            <Typography
                                sx={{
                                    color: "#94a3b8",
                                    fontSize: 13,
                                    mt: 0.6,
                                    lineHeight: 1.7,
                                }}
                            >
                                Sentinel-X detected several
                                suspicious activities this week.
                                Most were investigated automatically,
                                and your current protection status
                                remains healthy.
                            </Typography>

                        </Box>

                    </Box>

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
    icon,
    color,
}) {

    return (

        <Card>

            <CardContent
                sx={{
                    p: 2.5,
                }}
            >

                <Box
                    sx={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        gap: 1,
                    }}
                >

                    <Box>

                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 12,
                            }}
                        >
                            {title}
                        </Typography>


                        <Typography
                            sx={{
                                mt: 0.5,
                                fontSize: 28,
                                fontWeight: 800,
                            }}
                        >
                            {value}
                        </Typography>

                    </Box>


                    <Box
                        sx={{
                            width: 40,
                            height: 40,

                            borderRadius: "11px",

                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",

                            color: color,

                            background:
                                `${color}15`,
                        }}
                    >
                        {icon}
                    </Box>

                </Box>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* SUMMARY ROW */
/* ================================================================ */

function SummaryRow({
    title,
    value,
    status,
    warning,
}) {

    return (

        <Box
            sx={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 2,

                p: 1.7,

                borderRadius: "10px",

                background: "#0f172a",
            }}
        >

            <Typography
                sx={{
                    color: "#cbd5e1",
                    fontSize: 13,
                }}
            >
                {title}
            </Typography>


            <Box
                sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 1.5,
                }}
            >

                <Typography
                    sx={{
                        fontWeight: 700,
                    }}
                >
                    {value}
                </Typography>


                <Chip
                    label={
                        status
                    }
                    size="small"
                    sx={{
                        color:
                            warning
                                ? "#f59e0b"
                                : "#22c55e",

                        background:
                            warning
                                ? "rgba(245,158,11,0.10)"
                                : "rgba(34,197,94,0.10)",
                    }}
                />

            </Box>

        </Box>

    );

}


export default Reports;