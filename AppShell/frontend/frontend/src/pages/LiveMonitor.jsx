import {
    Box,
    Typography,
    Card,
    CardContent,
    Chip,
    Stack,
    Button,
    Alert,
    CircularProgress,
} from "@mui/material";

import {
    MemoryRounded,
    FolderRounded,
    LanguageRounded,
    SettingsRounded,
    RefreshRounded,
    CheckCircleRounded,
    ErrorRounded,
    WarningAmberRounded,
} from "@mui/icons-material";

import {
    useCallback,
    useEffect,
    useRef,
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

import {
    getSecurityRuntime,
    getLiveTelemetry,
} from "../api/sentinelApi";


/* ============================================================ */
/* CONFIGURATION */
/* ============================================================ */

const LIVE_POLL_INTERVAL = 2000;

const SUMMARY_REFRESH_INTERVAL = 10000;

const MAX_CHART_POINTS = 20;

/*
    Do not declare the collectors offline because of one
    temporary request failure.

    Three consecutive failures means approximately:

        3 * 2 seconds = 6 seconds
*/
const MAX_CONSECUTIVE_FAILURES = 3;


/* ============================================================ */
/* HELPERS */
/* ============================================================ */

function asCount(value) {

    const number = Number(
        value ?? 0
    );

    return Number.isFinite(
        number
    )
        ? Math.max(
            0,
            number
        )
        : 0;
}


function getCategoryCount(
    counts,
    category
) {

    return asCount(
        counts?.[category] ??
        counts?.[
            category.toLowerCase()
        ] ??
        0
    );
}


function normalizeCounts(
    counts = {}
) {

    return {

        process:
            getCategoryCount(
                counts,
                "PROCESS"
            ),

        file:
            getCategoryCount(
                counts,
                "FILE"
            ),

        network:
            getCategoryCount(
                counts,
                "NETWORK"
            ),

        system:
            getCategoryCount(
                counts,
                "REGISTRY"
            ) +
            getCategoryCount(
                counts,
                "SYSTEM"
            ) +
            getCategoryCount(
                counts,
                "STARTUP"
            ) +
            getCategoryCount(
                counts,
                "SECURITY"
            ) +
            getCategoryCount(
                counts,
                "RESPONSE"
            ),
    };
}


function calculateDelta(
    current,
    previous
) {

    /*
        Runtime counters can reset after the backend
        restarts.

        Never show negative activity.
    */

    if (
        current < previous
    ) {

        return 0;
    }

    return (
        current -
        previous
    );
}


function getShortTime() {

    return (
        new Date()
            .toLocaleTimeString(
                [],
                {
                    hour:
                        "2-digit",

                    minute:
                        "2-digit",

                    second:
                        "2-digit",
                }
            )
    );
}


function getCollectorStatus(
    collector
) {

    /*
        Current backend returns booleans:

            true  -> running
            false -> offline

        This helper also supports future object/string
        responses.
    */

    if (
        collector === true
    ) {

        return "ACTIVE";
    }


    if (
        collector === false
    ) {

        return "OFFLINE";
    }


    if (
        typeof collector ===
        "string"
    ) {

        return (
            collector
                .toUpperCase()
        );
    }


    if (
        collector &&
        typeof collector ===
        "object"
    ) {

        if (
            collector.status
        ) {

            return String(
                collector.status
            ).toUpperCase();
        }


        if (
            collector.healthy ===
            true
        ) {

            return "ACTIVE";
        }


        if (
            collector.healthy ===
            false
        ) {

            return "OFFLINE";
        }
    }


    return "UNKNOWN";
}


function getHighestActivityCategory(
    eventCounts
) {

    const categories = [

        {
            name:
                "Process",

            value:
                eventCounts.process,
        },

        {
            name:
                "File",

            value:
                eventCounts.file,
        },

        {
            name:
                "Network",

            value:
                eventCounts.network,
        },

        {
            name:
                "System",

            value:
                eventCounts.system,
        },
    ];


    categories.sort(
        (
            a,
            b
        ) =>
            b.value -
            a.value
    );


    if (
        categories.every(
            (item) =>
                item.value === 0
        )
    ) {

        return "None";
    }


    return (
        categories[0]
            .name
    );
}


/* ============================================================ */
/* LIVE MONITOR */
/* ============================================================ */

function LiveMonitor() {

    /* ======================================================== */
    /* STATE */
    /* ======================================================== */

    const [
        runtime,
        setRuntime,
    ] = useState(
        null
    );


    const [
        live,
        setLive,
    ] = useState(
        null
    );


    const [
        chartData,
        setChartData,
    ] = useState(
        []
    );


    const [
        loading,
        setLoading,
    ] = useState(
        true
    );


    const [
        refreshing,
        setRefreshing,
    ] = useState(
        false
    );


    const [
        error,
        setError,
    ] = useState(
        null
    );


    const [
        lastUpdated,
        setLastUpdated,
    ] = useState(
        null
    );


    /* ======================================================== */
    /* REFS */
    /* ======================================================== */

    const previousCounts =
        useRef(
            null
        );


    const previousTimestamp =
        useRef(
            null
        );


    const pollingInProgress =
        useRef(
            false
        );


    const lastSummaryFetch =
        useRef(
            0
        );


    const mountedRef =
        useRef(
            false
        );


    /*
        Prevent one temporary HTTP failure from making the
        dashboard rapidly switch:

            ACTIVE
              ↓
            OFFLINE
              ↓
            ACTIVE
    */
    const consecutiveLiveFailures =
        useRef(
            0
        );


    /* ======================================================== */
    /* UPDATE CHART */
/* ======================================================== */

    const updateChart =
        useCallback(
            (
                liveData
            ) => {

                const currentCounts =
                    normalizeCounts(
                        liveData
                            ?.runtime_counts
                        ||
                        {}
                    );


                const timestamp =
                    liveData
                        ?.timestamp
                    ||
                    null;


                const previous =
                    previousCounts
                        .current;


                const previousTime =
                    previousTimestamp
                        .current;


                /* ============================================ */
                /* FIRST SNAPSHOT */
                /* ============================================ */

                if (
                    previous ===
                    null
                ) {

                    previousCounts
                        .current =
                        currentCounts;


                    previousTimestamp
                        .current =
                        timestamp;


                    setChartData(
                        [
                            {
                                time:
                                    getShortTime(),

                                process:
                                    0,

                                file:
                                    0,

                                network:
                                    0,

                                system:
                                    0,
                            },
                        ]
                    );


                    return;
                }


                /* ============================================ */
                /* BACKEND RESTART / COUNTER RESET */
                /* ============================================ */

                const countersReset =
                    [
                        "process",
                        "file",
                        "network",
                        "system",
                    ]
                    .some(
                        (
                            key
                        ) =>
                            currentCounts[
                                key
                            ]
                            <
                            previous[
                                key
                            ]
                    );


                const currentParsedTime =
                    timestamp
                        ? Date.parse(
                            timestamp
                        )
                        : NaN;


                const previousParsedTime =
                    previousTime
                        ? Date.parse(
                            previousTime
                        )
                        : NaN;


                const timeWentBackwards =
                    Boolean(
                        Number.isFinite(
                            currentParsedTime
                        )
                        &&
                        Number.isFinite(
                            previousParsedTime
                        )
                        &&
                        currentParsedTime
                        <
                        previousParsedTime
                    );


                if (
                    countersReset
                    ||
                    timeWentBackwards
                ) {

                    previousCounts
                        .current =
                        currentCounts;


                    previousTimestamp
                        .current =
                        timestamp;


                    setChartData(
                        [
                            {
                                time:
                                    getShortTime(),

                                process:
                                    0,

                                file:
                                    0,

                                network:
                                    0,

                                system:
                                    0,
                            },
                        ]
                    );


                    return;
                }


                /* ============================================ */
                /* NEW ACTIVITY */
                /* ============================================ */

                const newPoint = {

                    time:
                        getShortTime(),


                    process:
                        calculateDelta(
                            currentCounts
                                .process,

                            previous
                                .process
                        ),


                    file:
                        calculateDelta(
                            currentCounts
                                .file,

                            previous
                                .file
                        ),


                    network:
                        calculateDelta(
                            currentCounts
                                .network,

                            previous
                                .network
                        ),


                    system:
                        calculateDelta(
                            currentCounts
                                .system,

                            previous
                                .system
                        ),
                };


                previousCounts
                    .current =
                    currentCounts;


                previousTimestamp
                    .current =
                    timestamp;


                setChartData(
                    (
                        previousChart
                    ) => [

                        ...previousChart,

                        newPoint,

                    ].slice(
                        -MAX_CHART_POINTS
                    )
                );

            },
            []
        );


    /* ======================================================== */
    /* LOAD LIVE BACKEND DATA */
    /* ======================================================== */

    const loadLiveData =
        useCallback(

            async (
                initialLoad =
                    false,

                forceSummary =
                    false
            ) => {

                /*
                    Prevent overlapping polling requests.

                    Example:

                    request takes 3 sec
                    poll interval = 2 sec

                    Without this protection multiple HTTP
                    requests would overlap.
                */

                if (
                    pollingInProgress
                        .current
                ) {

                    return;
                }


                pollingInProgress
                    .current =
                    true;


                try {

                    if (
                        mountedRef
                            .current
                        &&
                        initialLoad
                    ) {

                        setLoading(
                            true
                        );
                    }


                    if (
                        mountedRef
                            .current
                        &&
                        forceSummary
                    ) {

                        setRefreshing(
                            true
                        );
                    }


                    /* ======================================== */
                    /* 1. LIVE TELEMETRY */
                    /* ======================================== */

                    let liveResponse =
                        null;


                    try {

                        liveResponse =
                            await (
                                getLiveTelemetry()
                            );


                        /*
                            Reject malformed successful HTTP
                            responses.
                        */

                        if (
                            !liveResponse
                            ||
                            typeof liveResponse
                            !==
                            "object"
                        ) {

                            throw new Error(
                                "Invalid live telemetry response."
                            );
                        }


                        if (
                            !mountedRef
                                .current
                        ) {

                            return;
                        }


                        /*
                            Successful live telemetry request.

                            Reset transient failure counter.
                        */

                        consecutiveLiveFailures
                            .current =
                            0;


                        setLive(
                            liveResponse
                        );


                        updateChart(
                            liveResponse
                        );


                        setLastUpdated(
                            new Date()
                        );


                        /*
                            Clear connection error after a valid
                            telemetry snapshot arrives.
                        */

                        setError(
                            null
                        );

                    }
                    catch (
                        liveError
                    ) {

                        console.error(
                            "Live telemetry request failed:",
                            liveError
                        );


                        consecutiveLiveFailures
                            .current += 1;


                        if (
                            !mountedRef
                                .current
                        ) {

                            return;
                        }


                        /*
                            IMPORTANT

                            One failed poll does NOT mean the
                            collectors stopped.

                            This also makes the UI tolerate the
                            very small restart window produced by
                            uvicorn --reload.

                            We require three consecutive failures
                            before displaying OFFLINE.
                        */

                        if (
                            consecutiveLiveFailures
                                .current
                            >=
                            MAX_CONSECUTIVE_FAILURES
                        ) {

                            setLive(
                                null
                            );


                            previousCounts
                                .current =
                                null;


                            previousTimestamp
                                .current =
                                null;


                            setError(
                                liveError
                                    ?.response
                                    ?.data
                                    ?.detail
                                ||
                                liveError
                                    ?.response
                                    ?.data
                                    ?.message
                                ||
                                liveError
                                    ?.message
                                ||
                                (
                                    "Unable to load "
                                    +
                                    "Sentinel-X telemetry."
                                )
                            );
                        }


                        /*
                            Do not continue into supplemental
                            runtime requests if the main telemetry
                            call itself failed.
                        */

                        return;
                    }


                    /* ======================================== */
                    /* 2. SECURITY RUNTIME */
                    /* ======================================== */

                    const now =
                        Date.now();


                    const shouldRefreshSummary =
                        initialLoad
                        ||
                        forceSummary
                        ||
                        (
                            now
                            -
                            lastSummaryFetch
                                .current
                            >=
                            SUMMARY_REFRESH_INTERVAL
                        );


                    if (
                        shouldRefreshSummary
                    ) {

                        /*
                            IMPORTANT FIX

                            Previously the code used:

                                Promise.allSettled([
                                    runtimePromise
                                ])

                            but then read:

                                results[1].status

                            Only results[0] exists.

                            That caused:

                            Cannot read properties of undefined
                            (reading 'status')

                            Runtime fetch is isolated now so it
                            can never invalidate healthy live
                            telemetry.
                        */

                        try {

                            const runtimeResponse =
                                await (
                                    getSecurityRuntime()
                                );


                            if (
                                mountedRef
                                    .current
                                &&
                                runtimeResponse
                                &&
                                typeof runtimeResponse
                                ===
                                "object"
                            ) {

                                setRuntime(
                                    runtimeResponse
                                );
                            }

                        }
                        catch (
                            runtimeError
                        ) {

                            /*
                                Runtime summary failure does NOT
                                mean collectors are offline.
                            */

                            console.warn(
                                "Security runtime refresh failed:",
                                runtimeError
                            );
                        }


                        lastSummaryFetch
                            .current =
                            Date.now();
                    }

                }
                catch (
                    unexpectedError
                ) {

                    /*
                        Defensive final catch.

                        Do not destroy valid live state because
                        of a frontend programming/render issue.
                    */

                    console.error(
                        "Unexpected Live Monitor error:",
                        unexpectedError
                    );


                    if (
                        mountedRef
                            .current
                    ) {

                        setError(
                            unexpectedError
                                ?.message
                            ||
                            (
                                "Unexpected "
                                +
                                "Live Monitor error."
                            )
                        );
                    }

                }
                finally {

                    pollingInProgress
                        .current =
                        false;


                    if (
                        mountedRef
                            .current
                    ) {

                        setLoading(
                            false
                        );


                        setRefreshing(
                            false
                        );
                    }
                }
            },

            [
                updateChart,
            ]
        );


    /* ======================================================== */
    /* POLLING */
    /* ======================================================== */

    useEffect(
        () => {

            mountedRef
                .current =
                true;


            /*
                Immediate first load.
            */

            loadLiveData(
                true,
                true
            );


            /*
                Continuous 2-second polling.
            */

            const interval =
                setInterval(

                    () => {

                        loadLiveData(
                            false,
                            false
                        );

                    },

                    LIVE_POLL_INTERVAL
                );


            return () => {

                mountedRef
                    .current =
                    false;


                clearInterval(
                    interval
                );
            };

        },
        [
            loadLiveData,
        ]
    );


    /* ======================================================== */
    /* INITIAL LOADING */
    /* ======================================================== */

    if (
        loading
        &&
        !live
    ) {

        return (

            <Box
                sx={{
                    minHeight:
                        "65vh",

                    display:
                        "flex",

                    flexDirection:
                        "column",

                    alignItems:
                        "center",

                    justifyContent:
                        "center",

                    gap:
                        2,
                }}
            >

                <CircularProgress
                    sx={{
                        color:
                            "#22c55e",
                    }}
                />


                <Typography
                    sx={{
                        color:
                            "#94a3b8",
                    }}
                >
                    Loading live Sentinel-X telemetry...
                </Typography>

            </Box>
        );
    }


    /* ======================================================== */
    /* LIVE COUNTS */
    /* ======================================================== */

    const eventCounts =
        normalizeCounts(
            live
                ?.runtime_counts
            ||
            {}
        );


    const totalEvents =
        asCount(
            live
                ?.runtime_event_count
            ??
            live
                ?.total
        );


    /* ======================================================== */
    /* COLLECTOR STATUS */
    /* ======================================================== */

    const collectorInfo =
        live
            ?.collectors
        ||
        {};


    const processStatus =
        getCollectorStatus(
            collectorInfo
                .process
        );


    const fileStatus =
        getCollectorStatus(
            collectorInfo
                .file
        );


    const networkStatus =
        getCollectorStatus(
            collectorInfo
                .network
        );


    const registryStatus =
        getCollectorStatus(
            collectorInfo
                .registry
        );


    const liveStatus =
        String(
            live
                ?.status
            ||
            "OFFLINE"
        )
        .toUpperCase();


    const collectorsHealthy =
        Boolean(
            live
                ?.agent_running
            &&
            live
                ?.all_collectors_healthy
            &&
            liveStatus
            ===
            "ACTIVE"
        );


    const collectorsDegraded =
        Boolean(
            live
                ?.agent_running
            &&
            liveStatus
            ===
            "DEGRADED"
        );


    const runtimeStatus =
        String(
            runtime
                ?.status
            ||
            "UNKNOWN"
        )
        .toUpperCase();


    const runtimeHealthy =
        runtimeStatus
        ===
        "HEALTHY";


    const highActivitySource =
        getHighestActivityCategory(
            eventCounts
        );


    /* ======================================================== */
    /* HEADER STATUS */
    /* ======================================================== */

    let monitorStatusLabel =
        "COLLECTORS OFFLINE";


    let monitorStatusColor =
        "#ef4444";


    let monitorStatusBackground =
        "rgba(239,68,68,0.10)";


    let monitorStatusBorder =
        "1px solid rgba(239,68,68,0.25)";


    let monitorStatusIcon =
        <ErrorRounded />;


    if (
        collectorsHealthy
    ) {

        monitorStatusLabel =
            "LIVE MONITORING ACTIVE";


        monitorStatusColor =
            "#22c55e";


        monitorStatusBackground =
            "rgba(34,197,94,0.10)";


        monitorStatusBorder =
            "1px solid rgba(34,197,94,0.25)";


        monitorStatusIcon =
            <CheckCircleRounded />;
    }
    else if (
        collectorsDegraded
    ) {

        monitorStatusLabel =
            "MONITORING DEGRADED";


        monitorStatusColor =
            "#f59e0b";


        monitorStatusBackground =
            "rgba(245,158,11,0.10)";


        monitorStatusBorder =
            "1px solid rgba(245,158,11,0.25)";


        monitorStatusIcon =
            <WarningAmberRounded />;
    }


    /* ======================================================== */
    /* UI */
    /* ======================================================== */

    return (

        <Box>

            {/* ================================================= */}
            {/* ERROR */}
            {/* ================================================= */}

            {
                error && (

                    <Alert
                        severity="error"

                        sx={{
                            mb:
                                2,
                        }}
                    >

                        {
                            error
                        }

                    </Alert>
                )
            }


            {/* ================================================= */}
            {/* HEADER */}
            {/* ================================================= */}

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

                    mb:
                        3,
                }}
            >

                <Box>

                    <Typography
                        variant="h4"
                    >
                        Live Monitor
                    </Typography>


                    <Typography
                        sx={{
                            color:
                                "#94a3b8",

                            mt:
                                0.5,
                        }}
                    >
                        Continuous protection activity for this PC.
                    </Typography>

                </Box>


                <Chip
                    icon={
                        monitorStatusIcon
                    }

                    label={
                        monitorStatusLabel
                    }

                    sx={{
                        color:
                            monitorStatusColor,

                        background:
                            monitorStatusBackground,

                        border:
                            monitorStatusBorder,

                        fontWeight:
                            700,
                    }}
                />

            </Box>


            {/* ================================================= */}
            {/* STATUS CARDS */}
            {/* ================================================= */}

            <Box
                sx={{
                    display:
                        "grid",

                    gridTemplateColumns: {
                        xs:
                            "1fr",

                        sm:
                            "repeat(2, 1fr)",

                        lg:
                            "repeat(4, 1fr)",
                    },

                    gap:
                        2,

                    mb:
                        3,
                }}
            >

                <MetricCard
                    title="Process Events"

                    value={
                        eventCounts
                            .process
                    }

                    icon={
                        <MemoryRounded />
                    }

                    color="#3b82f6"
                />


                <MetricCard
                    title="File Events"

                    value={
                        eventCounts
                            .file
                    }

                    icon={
                        <FolderRounded />
                    }

                    color="#22c55e"
                />


                <MetricCard
                    title="Network Events"

                    value={
                        eventCounts
                            .network
                    }

                    icon={
                        <LanguageRounded />
                    }

                    color="#f59e0b"
                />


                <MetricCard
                    title="System Events"

                    value={
                        eventCounts
                            .system
                    }

                    icon={
                        <SettingsRounded />
                    }

                    color="#8b5cf6"
                />

            </Box>


            {/* ================================================= */}
            {/* ACTIVITY CHART */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb:
                        3,
                }}
            >

                <CardContent
                    sx={{
                        p:
                            3,
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

                            gap:
                                2,

                            flexWrap:
                                "wrap",

                            mb:
                                2,
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
                                    color:
                                        "#64748b",

                                    fontSize:
                                        13,

                                    mt:
                                        0.4,
                                }}
                            >
                                Real telemetry activity updates automatically every 2 seconds.
                            </Typography>

                        </Box>


                        <Button
                            startIcon={
                                refreshing
                                    ? (
                                        <CircularProgress
                                            size={
                                                16
                                            }
                                        />
                                    )
                                    : (
                                        <RefreshRounded />
                                    )
                            }

                            disabled={
                                refreshing
                            }

                            onClick={
                                () =>
                                    loadLiveData(
                                        false,
                                        true
                                    )
                            }

                            variant="outlined"
                        >
                            Live
                        </Button>

                    </Box>


                    <Box
                        sx={{
                            width:
                                "100%",

                            height:
                                360,
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

                                    allowDecimals={
                                        false
                                    }
                                />


                                <Tooltip
                                    contentStyle={{
                                        background:
                                            "#0f172a",

                                        border:
                                            (
                                                "1px solid "
                                                +
                                                "#1e293b"
                                            ),

                                        borderRadius:
                                            "10px",
                                    }}
                                />


                                <Legend />


                                <Line
                                    type="monotone"

                                    dataKey="process"

                                    stroke="#3b82f6"

                                    strokeWidth={
                                        2
                                    }

                                    dot={
                                        false
                                    }

                                    name="Process"

                                    isAnimationActive={
                                        false
                                    }
                                />


                                <Line
                                    type="monotone"

                                    dataKey="file"

                                    stroke="#22c55e"

                                    strokeWidth={
                                        2
                                    }

                                    dot={
                                        false
                                    }

                                    name="File"

                                    isAnimationActive={
                                        false
                                    }
                                />


                                <Line
                                    type="monotone"

                                    dataKey="network"

                                    stroke="#f59e0b"

                                    strokeWidth={
                                        2
                                    }

                                    dot={
                                        false
                                    }

                                    name="Network"

                                    isAnimationActive={
                                        false
                                    }
                                />


                                <Line
                                    type="monotone"

                                    dataKey="system"

                                    stroke="#8b5cf6"

                                    strokeWidth={
                                        2
                                    }

                                    dot={
                                        false
                                    }

                                    name="System"

                                    isAnimationActive={
                                        false
                                    }
                                />

                            </LineChart>

                        </ResponsiveContainer>

                    </Box>


                    {
                        lastUpdated && (

                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        12,

                                    mt:
                                        1.5,
                                }}
                            >

                                Last updated:{" "}

                                {
                                    lastUpdated
                                        .toLocaleTimeString()
                                }

                            </Typography>
                        )
                    }

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* MODULES + SUMMARY */}
            {/* ================================================= */}

            <Box
                sx={{
                    display:
                        "grid",

                    gridTemplateColumns: {
                        xs:
                            "1fr",

                        lg:
                            "1.1fr 1fr",
                    },

                    gap:
                        2,
                }}
            >

                {/* ============================================= */}
                {/* MONITORING MODULES */}
                {/* ============================================= */}

                <Card>

                    <CardContent
                        sx={{
                            p:
                                3,
                        }}
                    >

                        <Typography
                            variant="h6"

                            sx={{
                                mb:
                                    2,
                            }}
                        >
                            Monitoring Modules
                        </Typography>


                        <Stack
                            spacing={
                                1.5
                            }
                        >

                            <MonitorRow
                                icon={
                                    <MemoryRounded />
                                }

                                title="Process Monitoring"

                                description={
                                    (
                                        "Watching running applications "
                                        +
                                        "for suspicious behavior."
                                    )
                                }

                                status={
                                    processStatus
                                }
                            />


                            <MonitorRow
                                icon={
                                    <FolderRounded />
                                }

                                title="File Monitoring"

                                description={
                                    (
                                        "Watching suspicious file "
                                        +
                                        "changes and file actions."
                                    )
                                }

                                status={
                                    fileStatus
                                }
                            />


                            <MonitorRow
                                icon={
                                    <LanguageRounded />
                                }

                                title="Network Monitoring"

                                description={
                                    (
                                        "Watching live communication "
                                        +
                                        "and suspicious connections."
                                    )
                                }

                                status={
                                    networkStatus
                                }
                            />


                            <MonitorRow
                                icon={
                                    <SettingsRounded />
                                }

                                title="System Monitoring"

                                description={
                                    (
                                        "Watching important configuration "
                                        +
                                        "and startup changes."
                                    )
                                }

                                status={
                                    registryStatus
                                }
                            />

                        </Stack>

                    </CardContent>

                </Card>


                {/* ============================================= */}
                {/* LIVE SUMMARY */}
                {/* ============================================= */}

                <Card>

                    <CardContent
                        sx={{
                            p:
                                3,
                        }}
                    >

                        <Typography
                            variant="h6"

                            sx={{
                                mb:
                                    2,
                            }}
                        >
                            Live Summary
                        </Typography>


                        <SummaryRow
                            label="Live events this runtime"

                            value={
                                totalEvents
                                    .toLocaleString()
                            }
                        />


                        <SummaryRow
                            label="Process events"

                            value={
                                eventCounts
                                    .process
                                    .toLocaleString()
                            }
                        />


                        <SummaryRow
                            label="File events"

                            value={
                                eventCounts
                                    .file
                                    .toLocaleString()
                            }
                        />


                        <SummaryRow
                            label="Network events"

                            value={
                                eventCounts
                                    .network
                                    .toLocaleString()
                            }
                        />


                        <SummaryRow
                            label="System / registry events"

                            value={
                                eventCounts
                                    .system
                                    .toLocaleString()
                            }
                        />


                        <SummaryRow
                            label="High activity source"

                            value={
                                highActivitySource
                            }
                        />


                        <SummaryRow
                            label="Backend telemetry"

                            value={
                                liveStatus
                            }

                            safe={
                                collectorsHealthy
                            }
                        />


                        <SummaryRow
                            label="Runtime status"

                            value={
                                runtimeStatus
                            }

                            safe={
                                runtimeHealthy
                            }
                        />


                        <SummaryRow
                            label="Healthy collectors"

                            value={
                                `${
                                    asCount(
                                        live
                                            ?.healthy_collector_count
                                    )
                                } / ${
                                    asCount(
                                        live
                                            ?.expected_collector_count
                                    )
                                    ||
                                    4
                                }`
                            }

                            safe={
                                collectorsHealthy
                            }
                        />


                        <SummaryRow
                            label="Current device"

                            value="This PC"
                        />


                        <SummaryRow
                            label="Mode"

                            value={
                                live
                                    ?.collection_mode
                                ||
                                "Continuous Monitoring"
                            }
                        />

                    </CardContent>

                </Card>

            </Box>

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
                            2,
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
                            {
                                title
                            }
                        </Typography>


                        <Typography
                            sx={{
                                mt:
                                    0.5,

                                fontSize:
                                    30,

                                fontWeight:
                                    800,
                            }}
                        >
                            {
                                Number(
                                    value
                                    ??
                                    0
                                )
                                .toLocaleString()
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
                                `${color}15`,
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
/* MONITOR ROW */
/* ================================================================ */

function MonitorRow({
    icon,
    title,
    description,
    status,
}) {

    const normalizedStatus =
        String(
            status
            ||
            "UNKNOWN"
        )
        .toUpperCase();


    const active =
        [
            "ACTIVE",
            "RUNNING",
            "HEALTHY",
        ]
        .includes(
            normalizedStatus
        );


    const degraded =
        normalizedStatus
        ===
        "DEGRADED";


    const statusColor =
        active
            ? "#22c55e"

            : degraded
                ? "#f59e0b"

                : "#ef4444";


    return (

        <Box
            sx={{
                p:
                    1.7,

                borderRadius:
                    "12px",

                background:
                    "#0f172a",

                border:
                    "1px solid #1e293b",

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

            <Box
                sx={{
                    display:
                        "flex",

                    gap:
                        1.5,

                    alignItems:
                        "center",
                }}
            >

                <Box
                    sx={{
                        width:
                            40,

                        height:
                            40,

                        borderRadius:
                            "10px",

                        display:
                            "flex",

                        alignItems:
                            "center",

                        justifyContent:
                            "center",

                        color:
                            "#3b82f6",

                        background:
                            "rgba(59,130,246,0.10)",
                    }}
                >
                    {
                        icon
                    }
                </Box>


                <Box>

                    <Typography
                        sx={{
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
                            color:
                                "#64748b",

                            fontSize:
                                12,

                            mt:
                                0.3,
                        }}
                    >
                        {
                            description
                        }
                    </Typography>

                </Box>

            </Box>


            <Chip
                label={
                    normalizedStatus
                }

                size="small"

                sx={{
                    color:
                        statusColor,

                    background:
                        `${statusColor}15`,

                    fontWeight:
                        700,
                }}
            />

        </Box>
    );
}


/* ================================================================ */
/* SUMMARY ROW */
/* ================================================================ */

function SummaryRow({
    label,
    value,
    safe,
}) {

    return (

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

                py:
                    1.2,

                borderBottom:
                    "1px solid #1e293b",
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
                {
                    label
                }
            </Typography>


            <Typography
                sx={{
                    fontWeight:
                        700,

                    color:
                        safe
                            ? "#22c55e"
                            : "#f8fafc",
                }}
            >
                {
                    value
                }
            </Typography>

        </Box>
    );
}


export default LiveMonitor;