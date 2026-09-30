import {
    Box,
    Typography,
    Card,
    CardContent,
    Chip,
    Stack,
    Button,
} from "@mui/material";

import {
    MonitorHeartRounded,
    MemoryRounded,
    FolderRounded,
    LanguageRounded,
    SettingsRounded,
    RefreshRounded,
    CheckCircleRounded,
} from "@mui/icons-material";

import {
    useEffect,
    useState,
} from "react";

import {
    ResponsiveContainer,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
} from "recharts";


function LiveMonitor() {

    const [chartData, setChartData] =
        useState(
            generateInitialData()
        );

    const [lastUpdated, setLastUpdated] =
        useState(
            new Date()
                .toLocaleTimeString()
        );

    const [eventCounts, setEventCounts] =
        useState({
            process: 146,
            file: 88,
            network: 121,
            system: 54,
        });


    useEffect(() => {

        const interval =
            setInterval(() => {

                setChartData(
                    (previous) => {

                        const nextPoint = {
                            time: getShortTime(),
                            process:
                                randomBetween(
                                    40,
                                    95
                                ),
                            file:
                                randomBetween(
                                    20,
                                    75
                                ),
                            network:
                                randomBetween(
                                    35,
                                    90
                                ),
                            system:
                                randomBetween(
                                    15,
                                    60
                                ),
                        };

                        const updated =
                            [
                                ...previous,
                                nextPoint,
                            ];

                        return updated.slice(-20);

                    }
                );


                setEventCounts(
                    (previous) => ({
                        process:
                            previous.process
                            + randomBetween(1, 4),

                        file:
                            previous.file
                            + randomBetween(0, 3),

                        network:
                            previous.network
                            + randomBetween(1, 5),

                        system:
                            previous.system
                            + randomBetween(0, 2),
                    })
                );


                setLastUpdated(
                    new Date()
                        .toLocaleTimeString()
                );

            }, 2000);

        return () =>
            clearInterval(interval);

    }, []);


    const totalEvents =
        eventCounts.process
        + eventCounts.file
        + eventCounts.network
        + eventCounts.system;


    return (

        <Box>

            {/* ============================================= */}
            {/* HEADER */}
            {/* ============================================= */}

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

                    <Typography variant="h4">
                        Live Monitor
                    </Typography>

                    <Typography
                        sx={{
                            color: "#94a3b8",
                            mt: 0.5,
                        }}
                    >
                        Continuous protection activity for this PC.
                    </Typography>

                </Box>


                <Chip
                    icon={
                        <CheckCircleRounded />
                    }
                    label="LIVE MONITORING ACTIVE"
                    sx={{
                        color: "#22c55e",
                        background:
                            "rgba(34,197,94,0.10)",
                        border:
                            "1px solid rgba(34,197,94,0.25)",
                        fontWeight: 700,
                    }}
                />

            </Box>


            {/* ============================================= */}
            {/* STATUS CARDS */}
            {/* ============================================= */}

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: {
                        xs: "1fr",
                        sm: "repeat(2, 1fr)",
                        lg: "repeat(4, 1fr)",
                    },
                    gap: 2,
                    mb: 3,
                }}
            >

                <MetricCard
                    title="Process Events"
                    value={eventCounts.process}
                    icon={<MemoryRounded />}
                    color="#3b82f6"
                />

                <MetricCard
                    title="File Events"
                    value={eventCounts.file}
                    icon={<FolderRounded />}
                    color="#22c55e"
                />

                <MetricCard
                    title="Network Events"
                    value={eventCounts.network}
                    icon={<LanguageRounded />}
                    color="#f59e0b"
                />

                <MetricCard
                    title="System Events"
                    value={eventCounts.system}
                    icon={<SettingsRounded />}
                    color="#8b5cf6"
                />

            </Box>


            {/* ============================================= */}
            {/* LIVE LINE CHART */}
            {/* ============================================= */}

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
                            justifyContent: "space-between",
                            alignItems: "center",
                            gap: 2,
                            flexWrap: "wrap",
                            mb: 2,
                        }}
                    >

                        <Box>

                            <Typography
                                variant="h6"
                            >
                                Continuous Activity Monitoring
                            </Typography>

                            <Typography
                                sx={{
                                    color: "#64748b",
                                    fontSize: 13,
                                    mt: 0.4,
                                }}
                            >
                                Activity updates automatically every 2 seconds.
                            </Typography>

                        </Box>


                        <Button
                            startIcon={
                                <RefreshRounded />
                            }
                            variant="outlined"
                        >
                            Live
                        </Button>

                    </Box>


                    <Box
                        sx={{
                            width: "100%",
                            height: 360,
                        }}
                    >

                        <ResponsiveContainer>

                            <LineChart
                                data={
                                    chartData
                                }
                            >

                                <CartesianGrid
                                    strokeDasharray="3 3"
                                    stroke="#1e293b"
                                />

                                <XAxis
                                    dataKey="time"
                                    stroke="#64748b"
                                />

                                <YAxis
                                    stroke="#64748b"
                                    domain={[0, 100]}
                                />

                                <Tooltip
                                    contentStyle={{
                                        background: "#0f172a",
                                        border: "1px solid #1e293b",
                                        borderRadius: "10px",
                                    }}
                                />

                                <Legend />

                                <Line
                                    type="monotone"
                                    dataKey="process"
                                    stroke="#3b82f6"
                                    strokeWidth={2}
                                    dot={false}
                                    name="Process"
                                />

                                <Line
                                    type="monotone"
                                    dataKey="file"
                                    stroke="#22c55e"
                                    strokeWidth={2}
                                    dot={false}
                                    name="File"
                                />

                                <Line
                                    type="monotone"
                                    dataKey="network"
                                    stroke="#f59e0b"
                                    strokeWidth={2}
                                    dot={false}
                                    name="Network"
                                />

                                <Line
                                    type="monotone"
                                    dataKey="system"
                                    stroke="#8b5cf6"
                                    strokeWidth={2}
                                    dot={false}
                                    name="System"
                                />

                            </LineChart>

                        </ResponsiveContainer>

                    </Box>


                    <Typography
                        sx={{
                            color: "#64748b",
                            fontSize: 12,
                            mt: 1.5,
                        }}
                    >
                        Last updated: {lastUpdated}
                    </Typography>

                </CardContent>

            </Card>


            {/* ============================================= */}
            {/* MODULE STATUS + SUMMARY */}
            {/* ============================================= */}

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: {
                        xs: "1fr",
                        lg: "1.1fr 1fr",
                    },
                    gap: 2,
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
                            Monitoring Modules
                        </Typography>

                        <Stack spacing={1.5}>

                            <MonitorRow
                                icon={<MemoryRounded />}
                                title="Process Monitoring"
                                description="Watching running applications for suspicious behavior."
                                status="Active"
                            />

                            <MonitorRow
                                icon={<FolderRounded />}
                                title="File Monitoring"
                                description="Watching suspicious file changes and file actions."
                                status="Active"
                            />

                            <MonitorRow
                                icon={<LanguageRounded />}
                                title="Network Monitoring"
                                description="Watching live communication and suspicious connections."
                                status="Active"
                            />

                            <MonitorRow
                                icon={<SettingsRounded />}
                                title="System Monitoring"
                                description="Watching important configuration and startup changes."
                                status="Active"
                            />

                        </Stack>

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
                            Live Summary
                        </Typography>

                        <SummaryRow
                            label="Total monitored events"
                            value={totalEvents}
                        />

                        <SummaryRow
                            label="High activity source"
                            value="Network"
                        />

                        <SummaryRow
                            label="Monitoring status"
                            value="Running"
                            safe
                        />

                        <SummaryRow
                            label="Current device"
                            value="This PC"
                        />

                        <SummaryRow
                            label="Mode"
                            value="Continuous Monitoring"
                        />

                    </CardContent>

                </Card>

            </Box>

        </Box>

    );

}


/* ============================================================ */
/* METRIC CARD */
/* ============================================================ */

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
                        gap: 2,
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
                                fontSize: 30,
                                fontWeight: 800,
                            }}
                        >
                            {value}
                        </Typography>

                    </Box>


                    <Box
                        sx={{
                            width: 42,
                            height: 42,
                            borderRadius: "12px",
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


/* ============================================================ */
/* MONITOR ROW */
/* ============================================================ */

function MonitorRow({
    icon,
    title,
    description,
    status,
}) {

    return (

        <Box
            sx={{
                p: 1.7,
                borderRadius: "12px",
                background: "#0f172a",
                border: "1px solid #1e293b",

                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 2,
                flexWrap: "wrap",
            }}
        >

            <Box
                sx={{
                    display: "flex",
                    gap: 1.5,
                    alignItems: "center",
                }}
            >

                <Box
                    sx={{
                        width: 40,
                        height: 40,
                        borderRadius: "10px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "#3b82f6",
                        background:
                            "rgba(59,130,246,0.10)",
                    }}
                >
                    {icon}
                </Box>


                <Box>

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
                            mt: 0.3,
                        }}
                    >
                        {description}
                    </Typography>

                </Box>

            </Box>


            <Chip
                label={status}
                size="small"
                sx={{
                    color: "#22c55e",
                    background:
                        "rgba(34,197,94,0.10)",
                    fontWeight: 700,
                }}
            />

        </Box>

    );

}


/* ============================================================ */
/* SUMMARY ROW */
/* ============================================================ */

function SummaryRow({
    label,
    value,
    safe,
}) {

    return (

        <Box
            sx={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 2,
                py: 1.2,
                borderBottom: "1px solid #1e293b",
            }}
        >

            <Typography
                sx={{
                    color: "#94a3b8",
                    fontSize: 13,
                }}
            >
                {label}
            </Typography>

            <Typography
                sx={{
                    fontWeight: 700,
                    color: safe
                        ? "#22c55e"
                        : "#f8fafc",
                }}
            >
                {value}
            </Typography>

        </Box>

    );

}


/* ============================================================ */
/* HELPERS */
/* ============================================================ */

function generateInitialData() {

    const data = [];

    for (let i = 0; i < 12; i++) {

        data.push({
            time: `T${i + 1}`,
            process: randomBetween(40, 95),
            file: randomBetween(20, 75),
            network: randomBetween(35, 90),
            system: randomBetween(15, 60),
        });

    }

    return data;

}


function randomBetween(
    min,
    max
) {

    return Math.floor(
        Math.random() * (max - min + 1)
    ) + min;

}


function getShortTime() {

    const now = new Date();

    const hours =
        String(
            now.getHours()
        ).padStart(2, "0");

    const minutes =
        String(
            now.getMinutes()
        ).padStart(2, "0");

    const seconds =
        String(
            now.getSeconds()
        ).padStart(2, "0");

    return `${hours}:${minutes}:${seconds}`;

}


export default LiveMonitor;