import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Grid,
    LinearProgress,
    Stack,
    Chip,
    Divider,
} from "@mui/material";

import {
    SearchRounded,
    SecurityRounded,
    FolderRounded,
    PauseRounded,
    StopRounded,
    CheckCircleRounded,
    WarningAmberRounded,
    HistoryRounded,
} from "@mui/icons-material";

import {
    useEffect,
    useRef,
    useState,
} from "react";


function ScanCenter() {

    const [scanType, setScanType] =
        useState(null);

    const [scanStatus, setScanStatus] =
        useState("IDLE");

    const [progress, setProgress] =
        useState(0);

    const [filesChecked, setFilesChecked] =
        useState(0);

    const [threatsFound, setThreatsFound] =
        useState(0);

    const [elapsedSeconds, setElapsedSeconds] =
        useState(0);

    const intervalRef =
        useRef(null);


    // ============================================================
    // START SCAN
    // ============================================================

    const startScan = (type) => {

        clearInterval(
            intervalRef.current
        );

        setScanType(type);

        setScanStatus(
            "SCANNING"
        );

        setProgress(0);

        setFilesChecked(0);

        setThreatsFound(0);

        setElapsedSeconds(0);


        intervalRef.current =
            setInterval(() => {

                setProgress(
                    (previous) => {

                        const next =
                            previous + 2;


                        if (next >= 100) {

                            clearInterval(
                                intervalRef.current
                            );

                            setScanStatus(
                                "COMPLETED"
                            );

                            return 100;
                        }


                        return next;

                    }
                );


                setFilesChecked(
                    (previous) =>
                        previous
                        + Math.floor(
                            Math.random()
                            * 420
                            + 120
                        )
                );


                setElapsedSeconds(
                    (previous) =>
                        previous + 1
                );


                setThreatsFound(
                    (previous) => {

                        if (
                            previous === 0
                            &&
                            Math.random()
                            > 0.94
                        ) {
                            return 1;
                        }

                        return previous;

                    }
                );

            }, 300);

    };


    // ============================================================
    // PAUSE / RESUME
    // ============================================================

    const pauseScan = () => {

        if (
            scanStatus
            !== "SCANNING"
        ) {
            return;
        }


        clearInterval(
            intervalRef.current
        );

        setScanStatus(
            "PAUSED"
        );

    };


    const resumeScan = () => {

        if (
            scanStatus
            !== "PAUSED"
        ) {
            return;
        }


        setScanStatus(
            "SCANNING"
        );


        intervalRef.current =
            setInterval(() => {

                setProgress(
                    (previous) => {

                        const next =
                            previous + 2;


                        if (next >= 100) {

                            clearInterval(
                                intervalRef.current
                            );

                            setScanStatus(
                                "COMPLETED"
                            );

                            return 100;
                        }


                        return next;

                    }
                );


                setFilesChecked(
                    (previous) =>
                        previous
                        + Math.floor(
                            Math.random()
                            * 420
                            + 120
                        )
                );


                setElapsedSeconds(
                    (previous) =>
                        previous + 1
                );

            }, 300);

    };


    // ============================================================
    // CANCEL
    // ============================================================

    const cancelScan = () => {

        clearInterval(
            intervalRef.current
        );

        setScanStatus(
            "IDLE"
        );

        setScanType(null);

        setProgress(0);

        setFilesChecked(0);

        setThreatsFound(0);

        setElapsedSeconds(0);

    };


    // ============================================================
    // CLEANUP
    // ============================================================

    useEffect(
        () => {

            return () => {

                clearInterval(
                    intervalRef.current
                );

            };

        },
        []
    );


    // ============================================================
    // FORMAT TIME
    // ============================================================

    const formatTime = (
        totalSeconds
    ) => {

        const minutes =
            Math.floor(
                totalSeconds / 60
            );

        const seconds =
            totalSeconds % 60;


        return (
            `${String(minutes).padStart(2, "0")}:`
            +
            `${String(seconds).padStart(2, "0")}`
        );

    };


    // ============================================================
    // CURRENT LOCATION
    // ============================================================

    const currentLocation = (() => {

        if (
            !scanType
        ) {
            return "Waiting to start";
        }


        if (
            progress < 25
        ) {
            return "System processes";
        }


        if (
            progress < 50
        ) {
            return "Downloads and temporary files";
        }


        if (
            progress < 75
        ) {
            return "Installed applications";
        }


        return "System configuration";

    })();


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
                    Scan Center
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt: 0.5,
                    }}
                >
                    Scan your device for suspicious
                    activity and potential threats.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* SCAN OPTIONS */}
            {/* ================================================= */}

            <Grid
                container
                spacing={2}
                sx={{
                    mb: 3,
                }}
            >

                <Grid
                    item
                    xs={12}
                    md={4}
                >

                    <ScanOptionCard
                        title="Quick Scan"
                        description={
                            "Checks common locations where threats are most likely to appear."
                        }
                        duration="Usually a few minutes"
                        icon={
                            <SearchRounded />
                        }
                        recommended
                        disabled={
                            scanStatus
                            === "SCANNING"
                            ||
                            scanStatus
                            === "PAUSED"
                        }
                        onClick={
                            () =>
                                startScan(
                                    "Quick Scan"
                                )
                        }
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    md={4}
                >

                    <ScanOptionCard
                        title="Full Scan"
                        description={
                            "Checks your complete device and system activity."
                        }
                        duration="Takes longer"
                        icon={
                            <SecurityRounded />
                        }
                        disabled={
                            scanStatus
                            === "SCANNING"
                            ||
                            scanStatus
                            === "PAUSED"
                        }
                        onClick={
                            () =>
                                startScan(
                                    "Full Scan"
                                )
                        }
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    md={4}
                >

                    <ScanOptionCard
                        title="Custom Scan"
                        description={
                            "Choose specific files or folders to check."
                        }
                        duration="You choose the scope"
                        icon={
                            <FolderRounded />
                        }
                        disabled={
                            scanStatus
                            === "SCANNING"
                            ||
                            scanStatus
                            === "PAUSED"
                        }
                        onClick={
                            () =>
                                startScan(
                                    "Custom Scan"
                                )
                        }
                    />

                </Grid>

            </Grid>


            {/* ================================================= */}
            {/* ACTIVE SCAN */}
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

                            alignItems:
                                "center",

                            justifyContent:
                                "space-between",

                            gap: 2,

                            flexWrap:
                                "wrap",

                            mb: 3,
                        }}
                    >

                        <Box>

                            <Typography
                                variant="h6"
                            >
                                {
                                    scanStatus
                                    === "IDLE"
                                        ? "Ready to Scan"
                                        : scanType
                                }
                            </Typography>


                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        13,

                                    mt: 0.4,
                                }}
                            >
                                {
                                    scanStatus
                                    === "IDLE"
                                        ? "Choose a scan type above to begin."
                                        : scanStatus
                                }
                            </Typography>

                        </Box>


                        <ScanStatusChip
                            status={
                                scanStatus
                            }
                        />

                    </Box>


                    {/* Progress */}

                    <Box
                        sx={{
                            mb: 3,
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
                                Scan progress
                            </Typography>


                            <Typography
                                sx={{
                                    fontWeight:
                                        700,
                                }}
                            >
                                {
                                    progress
                                }%
                            </Typography>

                        </Box>


                        <LinearProgress
                            variant="determinate"

                            value={
                                progress
                            }

                            sx={{
                                height:
                                    10,

                                borderRadius:
                                    "10px",

                                background:
                                    "#1e293b",

                                "& .MuiLinearProgress-bar":
                                {
                                    background:
                                        threatsFound
                                        > 0
                                            ? "#f59e0b"
                                            : "#22c55e",
                                },
                            }}
                        />

                    </Box>


                    {/* Scan Metrics */}

                    <Grid
                        container
                        spacing={2}
                        sx={{
                            mb: 3,
                        }}
                    >

                        <Grid
                            item
                            xs={12}
                            sm={4}
                        >

                            <ScanMetric
                                label="Files Checked"
                                value={
                                    filesChecked.toLocaleString()
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            sm={4}
                        >

                            <ScanMetric
                                label="Threats Found"
                                value={
                                    threatsFound
                                }
                                warning={
                                    threatsFound
                                    > 0
                                }
                            />

                        </Grid>


                        <Grid
                            item
                            xs={12}
                            sm={4}
                        >

                            <ScanMetric
                                label="Elapsed Time"
                                value={
                                    formatTime(
                                        elapsedSeconds
                                    )
                                }
                            />

                        </Grid>

                    </Grid>


                    {/* Current Location */}

                    <Box
                        sx={{
                            p: 2,

                            borderRadius:
                                "12px",

                            background:
                                "#0f172a",

                            border:
                                "1px solid #1e293b",

                            mb: 3,
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
                            Currently checking
                        </Typography>


                        <Typography
                            sx={{
                                mt: 0.5,

                                fontWeight:
                                    600,
                            }}
                        >
                            {
                                currentLocation
                            }
                        </Typography>

                    </Box>


                    {/* Controls */}

                    <Stack
                        direction={{
                            xs:
                                "column",

                            sm:
                                "row",
                        }}
                        spacing={1.5}
                    >

                        {
                            scanStatus
                            === "SCANNING"
                            && (

                                <Button
                                    variant="outlined"

                                    startIcon={
                                        <PauseRounded />
                                    }

                                    onClick={
                                        pauseScan
                                    }
                                >
                                    Pause
                                </Button>

                            )
                        }


                        {
                            scanStatus
                            === "PAUSED"
                            && (

                                <Button
                                    variant="contained"

                                    onClick={
                                        resumeScan
                                    }
                                >
                                    Resume
                                </Button>

                            )
                        }


                        {
                            (
                                scanStatus
                                === "SCANNING"
                                ||
                                scanStatus
                                === "PAUSED"
                            )
                            && (

                                <Button
                                    variant="outlined"

                                    color="error"

                                    startIcon={
                                        <StopRounded />
                                    }

                                    onClick={
                                        cancelScan
                                    }
                                >
                                    Cancel Scan
                                </Button>

                            )
                        }


                        {
                            scanStatus
                            === "COMPLETED"
                            && (

                                <Button
                                    variant="contained"

                                    startIcon={
                                        <CheckCircleRounded />
                                    }

                                    onClick={
                                        () => {

                                            setScanStatus(
                                                "IDLE"
                                            );

                                            setScanType(
                                                null
                                            );

                                            setProgress(
                                                0
                                            );

                                        }
                                    }
                                >
                                    Done
                                </Button>

                            )
                        }

                    </Stack>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* RESULT */}
            {/* ================================================= */}

            {
                scanStatus
                === "COMPLETED"
                && (

                    <Card
                        sx={{
                            mb: 3,

                            borderColor:
                                threatsFound
                                > 0
                                    ? "rgba(245,158,11,0.40)"
                                    : "rgba(34,197,94,0.30)",
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

                                    alignItems:
                                        "center",

                                    gap: 2,
                                }}
                            >

                                {
                                    threatsFound
                                    > 0
                                        ? (

                                            <WarningAmberRounded
                                                sx={{
                                                    fontSize:
                                                        42,

                                                    color:
                                                        "#f59e0b",
                                                }}
                                            />

                                        )
                                        : (

                                            <CheckCircleRounded
                                                sx={{
                                                    fontSize:
                                                        42,

                                                    color:
                                                        "#22c55e",
                                                }}
                                            />

                                        )
                                }


                                <Box>

                                    <Typography
                                        variant="h6"
                                    >
                                        {
                                            threatsFound
                                            > 0
                                                ? `${threatsFound} threat requires review`
                                                : "No threats found"
                                        }
                                    </Typography>


                                    <Typography
                                        sx={{
                                            color:
                                                "#94a3b8",

                                            mt: 0.5,
                                        }}
                                    >
                                        {
                                            threatsFound
                                            > 0
                                                ? "Sentinel-X found suspicious activity that should be reviewed."
                                                : "Sentinel-X did not identify suspicious activity during this scan."
                                        }
                                    </Typography>

                                </Box>

                            </Box>

                        </CardContent>

                    </Card>

                )
            }


            {/* ================================================= */}
            {/* RECENT SCANS */}
            {/* ================================================= */}

            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                Recent Scans
            </Typography>


            <Card>

                <CardContent
                    sx={{
                        p: 0,
                    }}
                >

                    <RecentScan
                        icon={
                            <CheckCircleRounded />
                        }
                        title="Quick Scan"
                        description="No threats found"
                        time="Today"
                        safe
                    />


                    <Divider
                        sx={{
                            borderColor:
                                "#1e293b",
                        }}
                    />


                    <RecentScan
                        icon={
                            <WarningAmberRounded />
                        }
                        title="Full Scan"
                        description="1 suspicious item reviewed"
                        time="Yesterday"
                    />


                    <Divider
                        sx={{
                            borderColor:
                                "#1e293b",
                        }}
                    />


                    <RecentScan
                        icon={
                            <HistoryRounded />
                        }
                        title="Quick Scan"
                        description="No threats found"
                        time="3 days ago"
                        safe
                    />

                </CardContent>

            </Card>

        </Box>

    );

}


/* ================================================================ */
/* SCAN OPTION */
/* ================================================================ */

function ScanOptionCard({
    title,
    description,
    duration,
    icon,
    recommended,
    disabled,
    onClick,
}) {

    return (

        <Card
            sx={{
                height:
                    "100%",
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

                        mb: 2,
                    }}
                >

                    <Box
                        sx={{
                            width:
                                48,

                            height:
                                48,

                            borderRadius:
                                "13px",

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


                    {
                        recommended
                        && (

                            <Chip
                                label="Recommended"

                                size="small"

                                sx={{
                                    color:
                                        "#22c55e",

                                    background:
                                        "rgba(34,197,94,0.10)",
                                }}
                            />

                        )
                    }

                </Box>


                <Typography
                    sx={{
                        fontSize:
                            17,

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

                        mt: 0.8,

                        minHeight:
                            42,
                    }}
                >
                    {
                        description
                    }
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        fontSize:
                            12,

                        mt: 1.5,
                    }}
                >
                    {
                        duration
                    }
                </Typography>


                <Button
                    variant="outlined"

                    disabled={
                        disabled
                    }

                    onClick={
                        onClick
                    }

                    sx={{
                        mt: 2,
                    }}
                >
                    Start
                </Button>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* SCAN METRIC */
/* ================================================================ */

function ScanMetric({
    label,
    value,
    warning,
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
                    fontSize:
                        24,

                    fontWeight:
                        700,

                    mt: 0.5,

                    color:
                        warning
                            ? "#f59e0b"
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


/* ================================================================ */
/* STATUS CHIP */
/* ================================================================ */

function ScanStatusChip({
    status,
}) {

    const config = {

        IDLE: {
            label:
                "READY",

            color:
                "#94a3b8",
        },

        SCANNING: {
            label:
                "SCANNING",

            color:
                "#3b82f6",
        },

        PAUSED: {
            label:
                "PAUSED",

            color:
                "#f59e0b",
        },

        COMPLETED: {
            label:
                "COMPLETED",

            color:
                "#22c55e",
        },

    };


    const current =
        config[
            status
        ]
        || config.IDLE;


    return (

        <Chip
            label={
                current.label
            }

            sx={{
                color:
                    current.color,

                background:
                    `${current.color}15`,

                border:
                    `1px solid ${current.color}35`,

                fontWeight:
                    700,
            }}
        />

    );

}


/* ================================================================ */
/* RECENT SCAN */
/* ================================================================ */

function RecentScan({
    icon,
    title,
    description,
    time,
    safe,
}) {

    return (

        <Box
            sx={{
                px: 3,
                py: 2.5,

                display:
                    "flex",

                alignItems:
                    "center",

                justifyContent:
                    "space-between",

                gap: 2,
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
                        color:
                            safe
                                ? "#22c55e"
                                : "#f59e0b",
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

                            mt: 0.3,
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
                }}
            >
                {
                    time
                }
            </Typography>

        </Box>

    );

}


export default ScanCenter;