import {
    useCallback,
    useEffect,
    useMemo,
    useState,
} from "react";


import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    CircularProgress,
    Divider,
    Grid,
    Stack,
    Typography,
} from "@mui/material";


import {
    CheckCircleRounded,
    ChevronRightRounded,
    FolderRounded,
    LanguageRounded,
    PsychologyRounded,
    RefreshRounded,
    SearchRounded,
    SecurityRounded,
    SettingsApplicationsRounded,
    ShieldRounded,
    WarningAmberRounded,
} from "@mui/icons-material";


import {
    useNavigate,
} from "react-router-dom";


import {
    getLiveTelemetry,
    getUserProtectionModes,
    getUserSecurityStatus,
} from "../api/sentinelApi";


// ============================================================================
// CONFIG
// ============================================================================

const REFRESH_INTERVAL =
    10000;


// ============================================================================
// HELPERS
// ============================================================================

function object(
    value
) {

    return (
        value &&
        typeof value === "object" &&
        !Array.isArray(value)
    )
        ? value
        : {};

}


function collectorStatus(
    value
) {

    if (
        value === true
    ) {

        return "ACTIVE";

    }


    if (
        value === false
    ) {

        return "OFFLINE";

    }


    if (
        typeof value === "string"
    ) {

        return value
            .toUpperCase();

    }


    if (
        value &&
        typeof value === "object"
    ) {

        return String(
            value.status ||
            value.state ||
            "UNKNOWN"
        )
            .toUpperCase();

    }


    return "UNKNOWN";

}


function isActiveStatus(
    status
) {

    return [
        "ACTIVE",
        "RUNNING",
        "HEALTHY",
        "READY",
    ].includes(
        String(
            status || ""
        ).toUpperCase()
    );

}


function modeColor(
    mode
) {

    switch (
        String(
            mode || ""
        ).toUpperCase()
    ) {

        case "STRICT":
            return "#f97316";

        case "ASK_ME":
            return "#3b82f6";

        case "MONITOR_ONLY":
            return "#94a3b8";

        case "RECOMMENDED":
        default:
            return "#22c55e";

    }

}


function displayMode(
    key,
    metadata
) {

    return (
        metadata?.display_name ||
        String(
            key || ""
        )
            .replaceAll(
                "_",
                " "
            )
    );

}


// ============================================================================
// PAGE
// ============================================================================

function Protection() {

    const navigate =
        useNavigate();


    const [
        securityStatus,
        setSecurityStatus,
    ] =
        useState(null);


    const [
        protectionModes,
        setProtectionModes,
    ] =
        useState(null);


    const [
        telemetry,
        setTelemetry,
    ] =
        useState(null);


    const [
        loading,
        setLoading,
    ] =
        useState(true);


    const [
        refreshing,
        setRefreshing,
    ] =
        useState(false);


    const [
        error,
        setError,
    ] =
        useState(null);


    const [
        lastUpdated,
        setLastUpdated,
    ] =
        useState(null);


    // ========================================================================
    // LOAD
    // ========================================================================

    const loadProtection =
        useCallback(
            async (
                initial = false
            ) => {

                try {

                    if (
                        initial
                    ) {

                        setLoading(
                            true
                        );

                    }
                    else {

                        setRefreshing(
                            true
                        );

                    }


                    setError(
                        null
                    );


                    const [
                        statusResponse,
                        modesResponse,
                        telemetryResponse,
                    ] =
                        await Promise.all([

                            getUserSecurityStatus(),

                            getUserProtectionModes(),

                            getLiveTelemetry(),

                        ]);


                    setSecurityStatus(
                        statusResponse
                    );


                    setProtectionModes(
                        modesResponse
                    );


                    setTelemetry(
                        telemetryResponse
                    );


                    setLastUpdated(
                        new Date()
                    );

                }
                catch (
                    err
                ) {

                    console.error(
                        "Protection page error:",
                        err
                    );


                    setError(
                        err?.response?.data?.detail ||
                        err?.message ||
                        "Unable to load Sentinel-X protection status."
                    );

                }
                finally {

                    setLoading(
                        false
                    );


                    setRefreshing(
                        false
                    );

                }

            },
            []
        );


    // ========================================================================
    // INITIAL LOAD
    // ========================================================================

    useEffect(
        () => {

            loadProtection(
                true
            );

        },
        [
            loadProtection,
        ]
    );


    // ========================================================================
    // AUTO REFRESH
    // ========================================================================

    useEffect(
        () => {

            const interval =
                setInterval(
                    () => {

                        loadProtection(
                            false
                        );

                    },
                    REFRESH_INTERVAL
                );


            return () => {

                clearInterval(
                    interval
                );

            };

        },
        [
            loadProtection,
        ]
    );


    // ========================================================================
    // DERIVED STATE
    // ========================================================================

    const serviceReady =
        String(
            securityStatus?.status ||
            ""
        ).toUpperCase()
        ===
        "READY";


    const collectors =
        object(
            telemetry?.collectors
        );


    const processStatus =
        collectorStatus(
            collectors.process
        );


    const fileStatus =
        collectorStatus(
            collectors.file
        );


    const networkStatus =
        collectorStatus(
            collectors.network
        );


    const registryStatus =
        collectorStatus(
            collectors.registry
        );


    const modules =
        useMemo(
            () => [

                {
                    title:
                        "Process Protection",

                    description:
                        "Monitors running applications for suspicious behavior.",

                    icon:
                        <SettingsApplicationsRounded />,

                    status:
                        processStatus,
                },

                {
                    title:
                        "File Protection",

                    description:
                        "Checks files and file activity for potentially unsafe behavior.",

                    icon:
                        <FolderRounded />,

                    status:
                        fileStatus,
                },

                {
                    title:
                        "Network Protection",

                    description:
                        "Monitors network connections for suspicious communication.",

                    icon:
                        <LanguageRounded />,

                    status:
                        networkStatus,
                },

                {
                    title:
                        "System Protection",

                    description:
                        "Monitors Windows configuration, registry and persistence activity.",

                    icon:
                        <ShieldRounded />,

                    status:
                        registryStatus,
                },

            ],
            [
                processStatus,
                fileStatus,
                networkStatus,
                registryStatus,
            ]
        );


    const activeModuleCount =
        modules.filter(
            (
                module
            ) =>
                isActiveStatus(
                    module.status
                )
        ).length;


    const allModulesActive =
        (
            activeModuleCount ===
            modules.length
        );


    const defaultMode =
        protectionModes
            ?.default_mode
        ||
        "RECOMMENDED";


    const modes =
        Object.entries(
            object(
                protectionModes?.modes
            )
        );


    // ========================================================================
    // LOADING
    // ========================================================================

    if (
        loading &&
        !securityStatus
    ) {

        return (

            <Box
                sx={{
                    minHeight:
                        "60vh",

                    display:
                        "flex",

                    flexDirection:
                        "column",

                    alignItems:
                        "center",

                    justifyContent:
                        "center",

                    gap: 2,
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
                    Loading protection status...
                </Typography>

            </Box>

        );

    }


    return (

        <Box>

            {/* ============================================================= */}
            {/* HEADER */}
            {/* ============================================================= */}

            <Box
                sx={{
                    display:
                        "flex",

                    alignItems:
                        "flex-start",

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
                        variant="h4"
                    >
                        Protection
                    </Typography>


                    <Typography
                        sx={{
                            color:
                                "#94a3b8",

                            mt:
                                0.5,
                        }}
                    >
                        Manage how Sentinel-X monitors and
                        protects this device.
                    </Typography>


                    {
                        lastUpdated && (

                            <Typography
                                sx={{
                                    color:
                                        "#475569",

                                    fontSize:
                                        12,

                                    mt:
                                        0.7,
                                }}
                            >
                                Last updated{" "}
                                {
                                    lastUpdated
                                        .toLocaleTimeString()
                                }
                            </Typography>

                        )
                    }

                </Box>


                <Button
                    variant="outlined"

                    startIcon={
                        refreshing
                            ?
                            <CircularProgress
                                size={16}
                            />
                            :
                            <RefreshRounded />
                    }

                    disabled={
                        refreshing
                    }

                    onClick={
                        () =>
                            loadProtection(
                                false
                            )
                    }
                >
                    Refresh
                </Button>

            </Box>


            {/* ============================================================= */}
            {/* ERROR */}
            {/* ============================================================= */}

            {
                error && (

                    <Alert
                        severity="error"

                        sx={{
                            mb: 3,
                        }}
                    >
                        {error}
                    </Alert>

                )
            }


            {/* ============================================================= */}
            {/* PROTOTYPE SAFETY */}
            {/* ============================================================= */}

            {
                securityStatus
                    ?.simulation_only
                &&
                (

                    <Alert
                        severity="info"

                        sx={{
                            mb: 3,
                        }}
                    >
                        Sentinel-X is currently operating in
                        simulation-only protection mode.
                        Security decisions and protection plans
                        can be prepared, but no real containment
                        action is executed by this prototype.
                    </Alert>

                )
            }


            {/* ============================================================= */}
            {/* MAIN STATUS */}
            {/* ============================================================= */}

            <Card
                sx={{
                    mb:
                        3,

                    background:
                        allModulesActive
                            ?
                            "linear-gradient(135deg, #10251b, #111827)"
                            :
                            "linear-gradient(135deg, #2a1c0f, #111827)",
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

                            gap:
                                3,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                gap:
                                    2,
                            }}
                        >

                            <Box
                                sx={{
                                    width:
                                        68,

                                    height:
                                        68,

                                    borderRadius:
                                        "18px",

                                    display:
                                        "flex",

                                    alignItems:
                                        "center",

                                    justifyContent:
                                        "center",

                                    background:
                                        allModulesActive
                                            ?
                                            "rgba(34,197,94,0.12)"
                                            :
                                            "rgba(245,158,11,0.12)",
                                }}
                            >

                                {
                                    allModulesActive
                                        ?
                                        <SecurityRounded
                                            sx={{
                                                fontSize:
                                                    40,

                                                color:
                                                    "#22c55e",
                                            }}
                                        />
                                        :
                                        <WarningAmberRounded
                                            sx={{
                                                fontSize:
                                                    40,

                                                color:
                                                    "#f59e0b",
                                            }}
                                        />
                                }

                            </Box>


                            <Box>

                                <Typography
                                    variant="h5"

                                    sx={{
                                        mb:
                                            0.5,
                                    }}
                                >
                                    {
                                        allModulesActive
                                            ?
                                            "Your protection is active"
                                            :
                                            "Protection needs attention"
                                    }
                                </Typography>


                                <Typography
                                    sx={{
                                        color:
                                            "#94a3b8",

                                        maxWidth:
                                            650,
                                    }}
                                >
                                    Sentinel-X is monitoring
                                    process, file, network and
                                    system activity on this device.
                                </Typography>


                                <Stack
                                    direction="row"

                                    spacing={1}

                                    flexWrap="wrap"

                                    useFlexGap

                                    sx={{
                                        mt:
                                            1.5,
                                    }}
                                >

                                    <Chip
                                        size="small"

                                        label={
                                            serviceReady
                                                ?
                                                "SECURITY API READY"
                                                :
                                                "SECURITY API UNAVAILABLE"
                                        }

                                        sx={{
                                            color:
                                                serviceReady
                                                    ?
                                                    "#22c55e"
                                                    :
                                                    "#ef4444",

                                            background:
                                                serviceReady
                                                    ?
                                                    "rgba(34,197,94,0.10)"
                                                    :
                                                    "rgba(239,68,68,0.10)",
                                        }}
                                    />


                                    <Chip
                                        size="small"

                                        label={
                                            `${activeModuleCount}/${modules.length} MONITORS ACTIVE`
                                        }

                                        sx={{
                                            color:
                                                allModulesActive
                                                    ?
                                                    "#22c55e"
                                                    :
                                                    "#f59e0b",

                                            background:
                                                allModulesActive
                                                    ?
                                                    "rgba(34,197,94,0.10)"
                                                    :
                                                    "rgba(245,158,11,0.10)",
                                        }}
                                    />


                                    <Chip
                                        size="small"

                                        label={
                                            `${defaultMode.replaceAll(
                                                "_",
                                                " "
                                            )} MODE`
                                        }

                                        sx={{
                                            color:
                                                modeColor(
                                                    defaultMode
                                                ),

                                            background:
                                                `${modeColor(
                                                    defaultMode
                                                )}18`,
                                        }}
                                    />

                                </Stack>

                            </Box>

                        </Box>


                        <Button
                            variant="contained"

                            startIcon={
                                <SearchRounded />
                            }

                            onClick={
                                () =>
                                    navigate(
                                        "/scan"
                                    )
                            }

                            sx={{
                                background:
                                    "#22c55e",

                                color:
                                    "#04120a",

                                "&:hover": {
                                    background:
                                        "#16a34a",
                                },
                            }}
                        >
                            Run Security Scan
                        </Button>

                    </Box>

                </CardContent>

            </Card>


            {/* ============================================================= */}
            {/* PROTECTION MODE */}
            {/* ============================================================= */}

            <Box
                sx={{
                    mb:
                        2,
                }}
            >

                <Typography
                    variant="h6"
                >
                    Protection Mode
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
                    Sentinel-X uses protection modes to decide
                    how AI recommendations should be handled.
                </Typography>

            </Box>


            <Grid
                container

                spacing={2}

                sx={{
                    mb:
                        4,
                }}
            >

                {
                    modes.map(
                        ([
                            modeKey,
                            metadata,
                        ]) => {

                            const selected =
                                modeKey ===
                                defaultMode;


                            const color =
                                modeColor(
                                    modeKey
                                );


                            return (

                                <Grid
                                    item
                                    xs={12}
                                    md={6}

                                    key={
                                        modeKey
                                    }
                                >

                                    <Card
                                        sx={{
                                            height:
                                                "100%",

                                            border:
                                                selected
                                                    ?
                                                    `1px solid ${color}`
                                                    :
                                                    undefined,

                                            background:
                                                selected
                                                    ?
                                                    `${color}0d`
                                                    :
                                                    undefined,
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
                                                        2,
                                                }}
                                            >

                                                <Box>

                                                    <Typography
                                                        sx={{
                                                            fontWeight:
                                                                700,

                                                            fontSize:
                                                                16,
                                                        }}
                                                    >
                                                        {
                                                            displayMode(
                                                                modeKey,
                                                                metadata
                                                            )
                                                        }
                                                    </Typography>


                                                    <Typography
                                                        sx={{
                                                            color:
                                                                "#64748b",

                                                            fontSize:
                                                                13,

                                                            mt:
                                                                0.8,

                                                            lineHeight:
                                                                1.6,
                                                        }}
                                                    >
                                                        {
                                                            metadata
                                                                ?.description
                                                            ||
                                                            "Protection mode available."
                                                        }
                                                    </Typography>

                                                </Box>


                                                {
                                                    selected && (

                                                        <Chip
                                                            label="DEFAULT"

                                                            size="small"

                                                            sx={{
                                                                color,

                                                                background:
                                                                    `${color}18`,
                                                            }}
                                                        />

                                                    )
                                                }

                                            </Box>

                                        </CardContent>

                                    </Card>

                                </Grid>

                            );

                        }
                    )
                }

            </Grid>


            {/* ============================================================= */}
            {/* IMPORTANT READ-ONLY NOTE */}
            {/* ============================================================= */}

            <Alert
                severity="warning"

                sx={{
                    mb:
                        4,
                }}
            >
                Protection-mode configuration is currently
                read-only in 7D.9. The frontend is showing the
                backend policy correctly, but it will not pretend
                that a mode change has been saved until we add the
                dedicated user preference endpoint.
            </Alert>


            {/* ============================================================= */}
            {/* REAL-TIME PROTECTION */}
            {/* ============================================================= */}

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

                    mb:
                        2,
                }}
            >

                <Box>

                    <Typography
                        variant="h6"
                    >
                        Real-Time Protection
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
                        Live monitoring state reported by
                        the Sentinel-X endpoint agent.
                    </Typography>

                </Box>


                <Chip
                    label={
                        allModulesActive
                            ?
                            "ALL ACTIVE"
                            :
                            `${activeModuleCount} ACTIVE`
                    }

                    size="small"

                    sx={{
                        color:
                            allModulesActive
                                ?
                                "#22c55e"
                                :
                                "#f59e0b",

                        background:
                            allModulesActive
                                ?
                                "rgba(34,197,94,0.10)"
                                :
                                "rgba(245,158,11,0.10)",

                        border:
                            allModulesActive
                                ?
                                "1px solid rgba(34,197,94,0.25)"
                                :
                                "1px solid rgba(245,158,11,0.25)",

                        fontWeight:
                            700,
                    }}
                />

            </Box>


            <Grid
                container

                spacing={2}

                sx={{
                    mb:
                        4,
                }}
            >

                {
                    modules.map(
                        (
                            module
                        ) => (

                            <Grid
                                item
                                xs={12}
                                md={6}

                                key={
                                    module.title
                                }
                            >

                                <ProtectionModule
                                    {...module}
                                />

                            </Grid>

                        )
                    )
                }

            </Grid>


            {/* ============================================================= */}
            {/* AI PROTECTION */}
            {/* ============================================================= */}

            <Typography
                variant="h6"

                sx={{
                    mb:
                        2,
                }}
            >
                AI Protection
            </Typography>


            <Card>

                <CardContent
                    sx={{
                        p:
                            0,
                    }}
                >

                    <AIProtectionRow
                        title="Smart Threat Detection"

                        description="Combines endpoint detections and correlated security evidence."

                        status="Active"
                    />


                    <Divider
                        sx={{
                            borderColor:
                                "#1e293b",
                        }}
                    />


                    <AIProtectionRow
                        title="AI Risk Reasoning"

                        description="Evaluates grounded evidence before assigning user-facing risk."

                        status="Ready"
                    />


                    <Divider
                        sx={{
                            borderColor:
                                "#1e293b",
                        }}
                    />


                    <AIProtectionRow
                        title="Digital Twin Validation"

                        description="Simulates response plans before recommending protection."

                        status="Simulation"
                    />


                    <Divider
                        sx={{
                            borderColor:
                                "#1e293b",
                        }}
                    />


                    <AIProtectionRow
                        title="AI User Explanation"

                        description="Converts security evidence into understandable user-facing guidance."

                        status="Ready"
                    />

                </CardContent>

            </Card>


            {/* ============================================================= */}
            {/* ADVANCED */}
            {/* ============================================================= */}

            <Card
                sx={{
                    mt:
                        3,
                }}
            >

                <CardContent
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
                            Advanced Protection Details
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
                            View live monitoring, endpoint
                            telemetry and technical security
                            information.
                        </Typography>

                    </Box>


                    <Button
                        endIcon={
                            <ChevronRightRounded />
                        }

                        onClick={
                            () =>
                                navigate(
                                    "/live-monitor"
                                )
                        }

                        sx={{
                            color:
                                "#94a3b8",
                        }}
                    >
                        View Details
                    </Button>

                </CardContent>

            </Card>

        </Box>

    );

}


// ============================================================================
// PROTECTION MODULE
// ============================================================================

function ProtectionModule({
    title,
    description,
    icon,
    status,
}) {

    const active =
        isActiveStatus(
            status
        );


    const unknown =
        String(
            status || ""
        ).toUpperCase()
        ===
        "UNKNOWN";


    const color =
        active
            ?
            "#22c55e"
            :
            unknown
                ?
                "#94a3b8"
                :
                "#ef4444";


    return (

        <Card>

            <CardContent
                sx={{
                    p:
                        2.5,

                    display:
                        "flex",

                    alignItems:
                        "center",

                    justifyContent:
                        "space-between",

                    gap:
                        2,
                }}
            >

                <Box
                    sx={{
                        display:
                            "flex",

                        alignItems:
                            "center",

                        gap:
                            2,
                    }}
                >

                    <Box
                        sx={{
                            width:
                                44,

                            height:
                                44,

                            minWidth:
                                44,

                            borderRadius:
                                "12px",

                            display:
                                "flex",

                            alignItems:
                                "center",

                            justifyContent:
                                "center",

                            color,

                            background:
                                `${color}18`,
                        }}
                    >
                        {icon}
                    </Box>


                    <Box>

                        <Typography
                            sx={{
                                fontWeight:
                                    600,
                            }}
                        >
                            {title}
                        </Typography>


                        <Typography
                            sx={{
                                color:
                                    "#64748b",

                                fontSize:
                                    12,

                                mt:
                                    0.4,
                            }}
                        >
                            {description}
                        </Typography>

                    </Box>

                </Box>


                <Chip
                    label={
                        status
                    }

                    size="small"

                    sx={{
                        color,

                        background:
                            `${color}18`,

                        fontWeight:
                            700,
                    }}
                />

            </CardContent>

        </Card>

    );

}


// ============================================================================
// AI PROTECTION ROW
// ============================================================================

function AIProtectionRow({
    title,
    description,
    status,
}) {

    return (

        <Box
            sx={{
                px:
                    3,

                py:
                    2.5,

                display:
                    "flex",

                justifyContent:
                    "space-between",

                alignItems:
                    "center",

                gap:
                    2,
            }}
        >

            <Stack
                direction="row"

                spacing={2}

                alignItems="center"
            >

                <PsychologyRounded
                    sx={{
                        color:
                            "#8b5cf6",
                    }}
                />


                <Box>

                    <Typography
                        sx={{
                            fontWeight:
                                600,
                        }}
                    >
                        {title}
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
                        {description}
                    </Typography>

                </Box>

            </Stack>


            <Chip
                label={
                    status
                }

                size="small"

                sx={{
                    color:
                        "#22c55e",

                    background:
                        "rgba(34,197,94,0.10)",
                }}
            />

        </Box>

    );

}


export default Protection;