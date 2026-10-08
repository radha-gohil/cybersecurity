import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Chip,
    CircularProgress,
    Alert,
} from "@mui/material";

import {
    ShieldRounded,
    SearchRounded,
    WarningAmberRounded,
    PsychologyRounded,
    ApprovalRounded,
    CheckCircleRounded,
    RefreshRounded,
    SecurityRounded,
} from "@mui/icons-material";

import {
    useCallback,
    useEffect,
    useState,
} from "react";

import {
    useNavigate,
} from "react-router-dom";

import {
    getDashboardSummary,
    getHealth,

    // ============================================================
    // 7D.9 AI USER SECURITY
    // ============================================================

    getUserSecurityStatus,
    getUserProtectionModes,

} from "../api/sentinelApi";


function Dashboard() {

    const navigate =
        useNavigate();


    /* ============================================================ */
    /* STATE */
    /* ============================================================ */

    const [summary, setSummary] =
        useState(null);

    const [health, setHealth] =
        useState(null);


    /* ============================================================ */
    /* 7D.9 AI USER SECURITY STATE */
    /* ============================================================ */

    const [
        aiSecurityStatus,
        setAiSecurityStatus,
    ] =
        useState(null);


    const [
        protectionModes,
        setProtectionModes,
    ] =
        useState(null);


    /* ============================================================ */
    /* EXISTING DASHBOARD STATE */
    /* ============================================================ */

    const [loading, setLoading] =
        useState(true);

    const [refreshing, setRefreshing] =
        useState(false);

    const [error, setError] =
        useState(null);

    const [lastUpdated, setLastUpdated] =
        useState(null);


    /* ============================================================ */
    /* LOAD REAL BACKEND DATA */
    /* ============================================================ */

    const loadDashboard =
        useCallback(
            async (
                initialLoad = false
            ) => {

                try {

                    if (
                        initialLoad
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


                    /* ==================================================== */
                    /* EXISTING DASHBOARD DATA */
                    /* ==================================================== */

                    const [
                        healthResponse,
                        dashboardResponse,
                    ] =
                        await Promise.all([
                            getHealth(),
                            getDashboardSummary(),
                        ]);


                    console.log(
                        "SENTINEL-X HEALTH:",
                        healthResponse
                    );


                    console.log(
                        "SENTINEL-X DASHBOARD:",
                        dashboardResponse
                    );


                    setHealth(
                        healthResponse
                    );


                    setSummary(
                        dashboardResponse
                    );


                    /* ==================================================== */
                    /* OPTIONAL 7D.9 AI USER SECURITY DATA */
                    /* ==================================================== */
                    /*
                        IMPORTANT:

                        The AI API is isolated from the existing dashboard.

                        If the new 7D.9 API fails, the normal Sentinel-X
                        dashboard continues to work exactly as before.
                    */

                    try {

                        const [
                            aiStatusResult,
                            protectionModesResult,
                        ] =
                            await Promise.allSettled([

                                getUserSecurityStatus(),

                                getUserProtectionModes(),

                            ]);


                        if (
                            aiStatusResult.status
                            ===
                            "fulfilled"
                        ) {

                            setAiSecurityStatus(
                                aiStatusResult.value
                            );


                            console.log(
                                "SENTINEL-X USER SECURITY:",
                                aiStatusResult.value
                            );

                        }
                        else {

                            console.warn(
                                "User security status unavailable:",
                                aiStatusResult.reason
                            );

                        }


                        if (
                            protectionModesResult.status
                            ===
                            "fulfilled"
                        ) {

                            setProtectionModes(
                                protectionModesResult.value
                            );


                            console.log(
                                "SENTINEL-X PROTECTION MODES:",
                                protectionModesResult.value
                            );

                        }
                        else {

                            console.warn(
                                "Protection modes unavailable:",
                                protectionModesResult.reason
                            );

                        }

                    }
                    catch (
                        aiError
                    ) {

                        /*
                            Never fail the existing dashboard because
                            optional AI integration is unavailable.
                        */

                        console.warn(
                            "Optional AI security data unavailable:",
                            aiError
                        );

                    }


                    setLastUpdated(
                        new Date()
                    );

                }
                catch (err) {

                    console.error(
                        "Dashboard backend error:",
                        err
                    );


                    const message =
                        err?.response?.data?.detail
                        ||
                        err?.response?.data?.message
                        ||
                        err?.message
                        ||
                        "Unable to connect to Sentinel-X backend.";


                    setError(
                        message
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


    /* ============================================================ */
    /* INITIAL LOAD */
    /* ============================================================ */

    useEffect(
        () => {

            loadDashboard(
                true
            );

        },
        [
            loadDashboard,
        ]
    );


    /* ============================================================ */
    /* AUTOMATIC REFRESH EVERY 5 SECONDS */
    /* ============================================================ */

    useEffect(
        () => {

            const interval =
                setInterval(
                    () => {

                        loadDashboard(
                            false
                        );

                    },
                    5000
                );


            return () => {

                clearInterval(
                    interval
                );

            };

        },
        [
            loadDashboard,
        ]
    );


    /* ============================================================ */
    /* INITIAL LOADING */
    /* ============================================================ */

    if (
        loading
        &&
        !summary
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
                    Loading Sentinel-X security status...
                </Typography>

            </Box>

        );

    }


    /* ============================================================ */
    /* REAL BACKEND VALUES */
    /* ============================================================ */

    const totalDetected =
        readNumber(
            summary,
            [
                ["total_detected"],
                ["total_detected_incidents"],
                ["detected_incidents"],
                ["total_incidents"],
                ["incident_count"],
            ]
        );


    const awaitingInvestigation =
        readNumber(
            summary,
            [
                ["awaiting_investigation"],
                ["awaiting_investigation_count"],
                ["pending_investigation"],
            ]
        );


    const promoted =
        readNumber(
            summary,
            [
                ["promoted"],
                ["promoted_to_soc"],
                ["promoted_count"],
                ["soc_incidents"],
                ["soc_cases"],
            ]
        );


    const criticalThreats =
        readNumber(
            summary,
            [
                [
                    "severity_counts",
                    "CRITICAL",
                ],

                [
                    "severity_counts",
                    "critical",
                ],

                ["critical"],

                ["critical_count"],

                ["critical_incidents"],
            ]
        );


    const highThreats =
        readNumber(
            summary,
            [
                [
                    "severity_counts",
                    "HIGH",
                ],

                [
                    "severity_counts",
                    "high",
                ],

                ["high"],

                ["high_count"],

                ["high_incidents"],
            ]
        );


    const pendingApprovals =
        readNumber(
            summary,
            [
                ["pending_approvals"],
                ["pending_approval_count"],
                ["approvals_pending"],
            ]
        );


    const openTickets =
        readNumber(
            summary,
            [
                ["open_tickets"],
                ["open_ticket_count"],
                ["tickets_open"],
            ]
        );


    const responseActions =
        readNumber(
            summary,
            [
                ["response_actions"],
                ["response_action_count"],
                ["total_response_actions"],
            ]
        );


    /* ============================================================ */
    /* CURRENT RISK SCORE */
    /* ============================================================ */

    const riskScore =
        readNumber(
            summary,
            [
                ["risk_score"],
                ["current_risk_score"],
                ["overall_risk_score"],
                ["latest_risk_score"],

                [
                    "risk",
                    "score",
                ],

                [
                    "risk_assessment",
                    "risk_score",
                ],

                [
                    "latest_incident",
                    "risk_score",
                ],

                [
                    "security_state",
                    "risk_score",
                ],
            ]
        );


    const mitigationStatus =
        readValue(
            summary,
            [
                ["mitigation_status"],
                ["latest_mitigation_status"],
                ["verification_status"],
            ],
            "Monitoring"
        );


    /* ============================================================ */
    /* HEALTH STATUS */
    /* ============================================================ */

    const backendHealthy =
        isHealthy(
            health
        );


    /* ============================================================ */
    /* 7D.9 AI USER SECURITY VALUES */
    /* ============================================================ */

    const aiSecurityReady =
        String(
            aiSecurityStatus?.status
            ||
            ""
        )
            .toUpperCase()
        ===
        "READY";


    const protectionMode =
        protectionModes?.default_mode
        ||
        "RECOMMENDED";


    /* ============================================================ */
    /* EXISTING RISK VALUES */
    /* ============================================================ */

    const riskColor =
        getRiskColor(
            riskScore
        );


    const riskLevel =
        getRiskLevel(
            riskScore
        );


    return (

        <Box>

            {/* ================================================= */}
            {/* CONNECTION ERROR */}
            {/* ================================================= */}

            {
                error
                && (

                    <Alert
                        severity="error"

                        action={

                            <Button
                                color="inherit"

                                size="small"

                                onClick={
                                    () =>
                                        loadDashboard(
                                            false
                                        )
                                }
                            >
                                Retry
                            </Button>

                        }

                        sx={{
                            mb:
                                2,
                        }}
                    >
                        Backend connection issue:
                        {" "}
                        {error}
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
                        Dashboard
                    </Typography>


                    <Typography
                        sx={{
                            color:
                                "#94a3b8",

                            mt:
                                0.5,
                        }}
                    >
                        Sentinel-X protection overview for this PC.
                    </Typography>

                </Box>


                <Box
                    sx={{
                        display:
                            "flex",

                        alignItems:
                            "center",

                        gap:
                            1.5,
                    }}
                >

                    {
                        lastUpdated
                        && (

                            <Typography
                                sx={{
                                    color:
                                        "#64748b",

                                    fontSize:
                                        12,
                                }}
                            >
                                Updated
                                {" "}
                                {
                                    lastUpdated
                                        .toLocaleTimeString()
                                }
                            </Typography>

                        )
                    }


                    <Button
                        variant="outlined"

                        startIcon={

                            refreshing
                                ? (
                                    <CircularProgress
                                        size={16}
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
                                loadDashboard(
                                    false
                                )
                        }
                    >
                        Refresh
                    </Button>

                </Box>

            </Box>


            {/* ================================================= */}
            {/* MAIN PROTECTION STATUS */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb:
                        3,

                    background:
                        backendHealthy
                            ? "linear-gradient(135deg, #10251b, #111827)"
                            : "linear-gradient(135deg, #2a1518, #111827)",

                    borderColor:
                        backendHealthy
                            ? "rgba(34,197,94,0.30)"
                            : "rgba(239,68,68,0.30)",
                }}
            >

                <CardContent
                    sx={{
                        p:
                            4,
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
                                3,

                            flexWrap:
                                "wrap",
                        }}
                    >

                        {/* ===================================== */}
                        {/* LEFT */}
                        {/* ===================================== */}

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

                                    color:
                                        backendHealthy
                                            ? "#22c55e"
                                            : "#ef4444",

                                    background:
                                        backendHealthy
                                            ? "rgba(34,197,94,0.12)"
                                            : "rgba(239,68,68,0.12)",
                                }}
                            >

                                <ShieldRounded
                                    sx={{
                                        fontSize:
                                            40,
                                    }}
                                />

                            </Box>


                            <Box>

                                <Typography
                                    variant="h5"
                                >
                                    {
                                        backendHealthy
                                            ? "Your PC is protected"
                                            : "Protection service needs attention"
                                    }
                                </Typography>


                                <Typography
                                    sx={{
                                        color:
                                            "#94a3b8",

                                        mt:
                                            0.5,
                                    }}
                                >
                                    {
                                        backendHealthy
                                            ? "Sentinel-X continuous security monitoring is active."
                                            : "Sentinel-X cannot currently confirm backend protection status."
                                    }
                                </Typography>

                            </Box>

                        </Box>


                        {/* ===================================== */}
                        {/* RIGHT */}
                        {/* RISK SCORE + STATUS */}
                        {/* ===================================== */}

                        <Box
                            sx={{
                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                gap:
                                    2,

                                flexWrap:
                                    "wrap",

                                justifyContent:
                                    "flex-end",
                            }}
                        >

                            {/* CURRENT RISK SCORE */}

                            <Box
                                sx={{
                                    px:
                                        2.5,

                                    py:
                                        1.4,

                                    borderRadius:
                                        "12px",

                                    background:
                                        `${riskColor}10`,

                                    border:
                                        `1px solid ${riskColor}30`,

                                    minWidth:
                                        145,
                                }}
                            >

                                <Typography
                                    sx={{
                                        color:
                                            "#94a3b8",

                                        fontSize:
                                            11,

                                        fontWeight:
                                            600,
                                    }}
                                >
                                    CURRENT RISK SCORE
                                </Typography>


                                <Box
                                    sx={{
                                        display:
                                            "flex",

                                        alignItems:
                                            "baseline",

                                        gap:
                                            0.7,

                                        mt:
                                            0.3,
                                    }}
                                >

                                    <Typography
                                        sx={{
                                            fontSize:
                                                28,

                                            fontWeight:
                                                800,

                                            color:
                                                riskColor,

                                            lineHeight:
                                                1,
                                        }}
                                    >
                                        {riskScore}
                                    </Typography>


                                    <Typography
                                        sx={{
                                            color:
                                                "#64748b",

                                            fontSize:
                                                12,
                                        }}
                                    >
                                        /100
                                    </Typography>

                                </Box>


                                <Typography
                                    sx={{
                                        mt:
                                            0.5,

                                        fontSize:
                                            11,

                                        fontWeight:
                                            700,

                                        color:
                                            riskColor,
                                    }}
                                >
                                    {riskLevel} RISK
                                </Typography>

                            </Box>


                            {/* PROTECTION CHIP */}

                            <Chip
                                icon={

                                    backendHealthy
                                        ? (
                                            <CheckCircleRounded />
                                        )
                                        : (
                                            <WarningAmberRounded />
                                        )

                                }

                                label={
                                    backendHealthy
                                        ? "PROTECTION ACTIVE"
                                        : "NEEDS ATTENTION"
                                }

                                sx={{
                                    color:
                                        backendHealthy
                                            ? "#22c55e"
                                            : "#ef4444",

                                    background:
                                        backendHealthy
                                            ? "rgba(34,197,94,0.10)"
                                            : "rgba(239,68,68,0.10)",

                                    border:
                                        backendHealthy
                                            ? "1px solid rgba(34,197,94,0.25)"
                                            : "1px solid rgba(239,68,68,0.25)",

                                    fontWeight:
                                        700,
                                }}
                            />

                        </Box>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* PRIMARY DASHBOARD CARDS */}
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
                    title="Threats Detected"
                    value={
                        totalDetected
                    }
                    color="#ef4444"
                    icon={
                        <WarningAmberRounded />
                    }
                />


                <MetricCard
                    title="AI Investigations"
                    value={
                        awaitingInvestigation
                    }
                    color="#8b5cf6"
                    icon={
                        <PsychologyRounded />
                    }
                />


                <MetricCard
                    title="Needs Approval"
                    value={
                        pendingApprovals
                    }
                    color="#f59e0b"
                    icon={
                        <ApprovalRounded />
                    }
                />


                <MetricCard
                    title="Security Cases"
                    value={
                        promoted
                    }
                    color="#22c55e"
                    icon={
                        <SecurityRounded />
                    }
                />

            </Box>


            {/* ================================================= */}
            {/* SECURITY STATUS */}
            {/* ================================================= */}

            <Box
                sx={{
                    display:
                        "grid",

                    gridTemplateColumns:
                        {
                            xs:
                                "1fr",

                            lg:
                                "1.3fr 1fr",
                        },

                    gap:
                        2,

                    mb:
                        3,
                }}
            >

                {/* ================================================= */}
                {/* THREAT OVERVIEW */}
                {/* ================================================= */}

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
                            Security Overview
                        </Typography>


                        <StatusRow
                            label="Current Risk Score"
                            value={
                                `${riskScore}/100`
                            }
                            color={
                                riskColor
                            }
                            raw
                        />


                        <StatusRow
                            label="Critical Threats"
                            value={
                                criticalThreats
                            }
                            color="#ef4444"
                        />


                        <StatusRow
                            label="High Risk Threats"
                            value={
                                highThreats
                            }
                            color="#f97316"
                        />


                        <StatusRow
                            label="Awaiting Investigation"
                            value={
                                awaitingInvestigation
                            }
                            color="#f59e0b"
                        />


                        <StatusRow
                            label="Open Tickets"
                            value={
                                openTickets
                            }
                            color="#3b82f6"
                        />


                        <StatusRow
                            label="Response Actions"
                            value={
                                responseActions
                            }
                            color="#22c55e"
                        />


                        {/* ========================================= */}
                        {/* 7D.9 AI USER SECURITY — ADDED ONLY */}
                        {/* ========================================= */}

                        <StatusRow
                            label="AI Security Service"
                            value={
                                aiSecurityReady
                                    ? "Ready"
                                    : "Unavailable"
                            }
                            color={
                                aiSecurityReady
                                    ? "#22c55e"
                                    : "#f59e0b"
                            }
                            raw
                        />


                        <StatusRow
                            label="Protection Mode"
                            value={
                                formatStatus(
                                    protectionMode
                                )
                            }
                            color="#8b5cf6"
                            raw
                        />


                        <Button
                            variant="outlined"

                            fullWidth

                            sx={{
                                mt:
                                    2,
                            }}

                            onClick={
                                () =>
                                    navigate(
                                        "/threats"
                                    )
                            }
                        >
                            Review Threats
                        </Button>

                    </CardContent>

                </Card>


                {/* ================================================= */}
                {/* QUICK ACTIONS */}
                {/* ================================================= */}

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
                            Quick Actions
                        </Typography>


                        <Button
                            variant="contained"

                            fullWidth

                            startIcon={
                                <SearchRounded />
                            }

                            onClick={
                                () =>
                                    navigate(
                                        "/live-monitor"
                                    )
                            }

                            sx={{
                                mb:
                                    1.5,

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
                            Open Live Monitor
                        </Button>


                        <Button
                            variant="outlined"

                            fullWidth

                            startIcon={
                                <WarningAmberRounded />
                            }

                            onClick={
                                () =>
                                    navigate(
                                        "/threats"
                                    )
                            }

                            sx={{
                                mb:
                                    1.5,
                            }}
                        >
                            Review Threats
                        </Button>


                        <Button
                            variant="outlined"

                            fullWidth

                            startIcon={
                                <PsychologyRounded />
                            }

                            onClick={
                                () =>
                                    navigate(
                                        "/ai-security"
                                    )
                            }

                            sx={{
                                mb:
                                    1.5,
                            }}
                        >
                            AI Investigation
                        </Button>


                        <Button
                            variant="outlined"

                            fullWidth

                            startIcon={
                                <ApprovalRounded />
                            }

                            onClick={
                                () =>
                                    navigate(
                                        "/approvals"
                                    )
                            }
                        >
                            Review Approvals
                        </Button>

                    </CardContent>

                </Card>

            </Box>


            {/* ================================================= */}
            {/* MITIGATION STATUS */}
            {/* ================================================= */}

            <Card>

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
                                Protection Verification
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
                                Latest Sentinel-X mitigation and
                                response verification status.
                            </Typography>

                        </Box>


                        <Chip
                            label={
                                formatStatus(
                                    mitigationStatus
                                )
                            }

                            sx={{
                                color:
                                    getMitigationColor(
                                        mitigationStatus
                                    ),

                                background:
                                    `${getMitigationColor(
                                        mitigationStatus
                                    )}15`,

                                fontWeight:
                                    700,
                            }}
                        />

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
                            {title}
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
                                formatNumber(
                                    value
                                )
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

                        {icon}

                    </Box>

                </Box>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* STATUS ROW */
/* ================================================================ */

function StatusRow({
    label,
    value,
    color,
    raw = false,
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

                py:
                    1.2,

                borderBottom:
                    "1px solid #1e293b",
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
                }}
            >

                <Box
                    sx={{
                        width:
                            8,

                        height:
                            8,

                        borderRadius:
                            "50%",

                        background:
                            color,
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
                    {label}
                </Typography>

            </Box>


            <Typography
                sx={{
                    fontWeight:
                        700,

                    color:
                        raw
                            ? color
                            : "inherit",
                }}
            >
                {
                    raw
                        ? value
                        : formatNumber(
                            value
                        )
                }
            </Typography>

        </Box>

    );

}


/* ================================================================ */
/* READ BACKEND VALUE */
/* ================================================================ */

function readValue(
    object,
    paths,
    fallback = null
) {

    if (
        !object
    ) {
        return fallback;
    }


    for (
        const path
        of paths
    ) {

        let current =
            object;


        for (
            const key
            of path
        ) {

            if (
                current
                === null
                ||
                current
                === undefined
            ) {

                current =
                    undefined;

                break;

            }


            current =
                current[key];

        }


        if (
            current
            !== undefined
            &&
            current
            !== null
        ) {

            return current;

        }

    }


    return fallback;

}


/* ================================================================ */
/* READ NUMBER */
/* ================================================================ */

function readNumber(
    object,
    paths,
    fallback = 0
) {

    const value =
        readValue(
            object,
            paths,
            fallback
        );


    if (
        typeof value
        === "number"
    ) {

        return value;

    }


    if (
        typeof value
        === "string"
        &&
        value.trim()
        !== ""
        &&
        !Number.isNaN(
            Number(value)
        )
    ) {

        return Number(
            value
        );

    }


    return fallback;

}


/* ================================================================ */
/* HEALTH CHECK */
/* ================================================================ */

function isHealthy(
    health
) {

    if (
        !health
    ) {

        return false;

    }


    const status =
        String(
            health.status
            ??
            health.health
            ??
            health.state
            ??
            ""
        )
            .toUpperCase();


    if (
        [
            "HEALTHY",
            "OK",
            "ACTIVE",
            "RUNNING",
            "READY",
        ].includes(
            status
        )
    ) {

        return true;

    }


    return true;

}


/* ================================================================ */
/* RISK COLOR */
/* ================================================================ */

function getRiskColor(
    riskScore
) {

    if (
        riskScore >= 80
    ) {

        return "#ef4444";

    }


    if (
        riskScore >= 60
    ) {

        return "#f97316";

    }


    if (
        riskScore >= 40
    ) {

        return "#f59e0b";

    }


    if (
        riskScore >= 20
    ) {

        return "#3b82f6";

    }


    return "#22c55e";

}


/* ================================================================ */
/* RISK LEVEL */
/* ================================================================ */

function getRiskLevel(
    riskScore
) {

    if (
        riskScore >= 80
    ) {

        return "CRITICAL";

    }


    if (
        riskScore >= 60
    ) {

        return "HIGH";

    }


    if (
        riskScore >= 40
    ) {

        return "MEDIUM";

    }


    if (
        riskScore >= 20
    ) {

        return "LOW";

    }


    return "SAFE";

}


/* ================================================================ */
/* NUMBER FORMAT */
/* ================================================================ */

function formatNumber(
    value
) {

    const number =
        Number(
            value
        );


    if (
        Number.isNaN(
            number
        )
    ) {

        return 0;

    }


    return number
        .toLocaleString();

}


/* ================================================================ */
/* STATUS FORMAT */
/* ================================================================ */

function formatStatus(
    status
) {

    if (
        !status
    ) {

        return "Monitoring";

    }


    return String(
        status
    )
        .replaceAll(
            "_",
            " "
        )
        .toLowerCase()
        .replace(
            /\b\w/g,
            (character) =>
                character
                    .toUpperCase()
        );

}


/* ================================================================ */
/* MITIGATION STATUS COLOR */
/* ================================================================ */

function getMitigationColor(
    status
) {

    const value =
        String(
            status
            ?? ""
        )
            .toUpperCase();


    if (
        value.includes(
            "VERIFIED"
        )
        ||
        value.includes(
            "COMPLETE"
        )
        ||
        value.includes(
            "SUCCESS"
        )
    ) {

        return "#22c55e";

    }


    if (
        value.includes(
            "FAIL"
        )
        ||
        value.includes(
            "ERROR"
        )
    ) {

        return "#ef4444";

    }


    if (
        value.includes(
            "PENDING"
        )
        ||
        value.includes(
            "REVIEW"
        )
    ) {

        return "#f59e0b";

    }


    return "#3b82f6";

}


export default Dashboard;