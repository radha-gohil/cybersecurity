import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Chip,
    LinearProgress,
    Stack,
} from "@mui/material";

import {
    ComputerRounded,
    SecurityRounded,
    CheckCircleRounded,
    WarningAmberRounded,
    ArrowForwardRounded,
    SyncRounded,
} from "@mui/icons-material";

import {
    useNavigate,
} from "react-router-dom";


const devices = [
    {
        id: "DEVICE-001",
        name: "Personal Laptop",
        os: "Windows 11",
        status: "PROTECTED",
        securityScore: 94,
        threats: 1,
        lastChecked: "Just now",
        monitoring: true,
    },

    {
        id: "DEVICE-002",
        name: "Office Laptop",
        os: "Windows 11",
        status: "NEEDS_ATTENTION",
        securityScore: 82,
        threats: 2,
        lastChecked: "8 minutes ago",
        monitoring: true,
    },
];


function Devices() {

    const navigate =
        useNavigate();


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
                    Devices
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt: 0.5,
                    }}
                >
                    View the security health of devices
                    protected by Sentinel-X.
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
                            xs: "1fr",
                            sm: "repeat(3, 1fr)",
                        },

                    gap: 2,

                    mb: 3,
                }}
            >

                <SummaryCard
                    title="Protected Devices"
                    value="2"
                    color="#22c55e"
                />


                <SummaryCard
                    title="Devices Needing Attention"
                    value="1"
                    color="#f59e0b"
                />


                <SummaryCard
                    title="Active Threats"
                    value="3"
                    color="#ef4444"
                />

            </Box>


            {/* ================================================= */}
            {/* DEVICE CARDS */}
            {/* ================================================= */}

            <Stack
                spacing={2}
            >

                {
                    devices.map(
                        (device) => (

                            <DeviceCard
                                key={
                                    device.id
                                }

                                device={
                                    device
                                }

                                onView={
                                    () =>
                                        navigate(
                                            `/devices/${device.id}`
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
/* DEVICE CARD */
/* ================================================================ */

function DeviceCard({
    device,
    onView,
}) {

    const statusConfig =
        getStatusConfig(
            device.status
        );


    return (

        <Card
            sx={{
                borderColor:
                    `${statusConfig.color}35`,
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

                        gap: 3,

                        flexWrap:
                            "wrap",
                    }}
                >

                    {/* LEFT */}

                    <Box
                        sx={{
                            display:
                                "flex",

                            gap: 2,

                            flex: 1,

                            minWidth:
                                280,
                        }}
                    >

                        <Box
                            sx={{
                                width:
                                    56,

                                height:
                                    56,

                                minWidth:
                                    56,

                                borderRadius:
                                    "16px",

                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                justifyContent:
                                    "center",

                                color:
                                    statusConfig.color,

                                background:
                                    `${statusConfig.color}12`,
                            }}
                        >

                            <ComputerRounded
                                sx={{
                                    fontSize:
                                        32,
                                }}
                            />

                        </Box>


                        <Box
                            sx={{
                                flex:
                                    1,
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

                                    flexWrap:
                                        "wrap",
                                }}
                            >

                                <Typography
                                    sx={{
                                        fontSize:
                                            19,

                                        fontWeight:
                                            700,
                                    }}
                                >
                                    {
                                        device.name
                                    }
                                </Typography>


                                <Chip
                                    label={
                                        statusConfig.label
                                    }

                                    size="small"

                                    sx={{
                                        color:
                                            statusConfig.color,

                                        background:
                                            `${statusConfig.color}12`,

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

                                    mt:
                                        0.5,
                                }}
                            >
                                {
                                    device.os
                                }
                            </Typography>


                            {/* SCORE */}

                            <Box
                                sx={{
                                    mt: 2,

                                    maxWidth:
                                        500,
                                }}
                            >

                                <Box
                                    sx={{
                                        display:
                                            "flex",

                                        justifyContent:
                                            "space-between",

                                        mb:
                                            0.8,
                                    }}
                                >

                                    <Typography
                                        sx={{
                                            color:
                                                "#94a3b8",

                                            fontSize:
                                                12,
                                        }}
                                    >
                                        Security Score
                                    </Typography>


                                    <Typography
                                        sx={{
                                            fontWeight:
                                                700,
                                        }}
                                    >
                                        {
                                            device.securityScore
                                        } / 100
                                    </Typography>

                                </Box>


                                <LinearProgress
                                    variant="determinate"

                                    value={
                                        device.securityScore
                                    }

                                    sx={{
                                        height:
                                            8,

                                        borderRadius:
                                            10,

                                        background:
                                            "#1e293b",

                                        "& .MuiLinearProgress-bar":
                                        {
                                            background:
                                                statusConfig.color,
                                        },
                                    }}
                                />

                            </Box>


                            {/* DETAILS */}

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

                                    gap:
                                        1.5,

                                    mt:
                                        2,
                                }}
                            >

                                <InfoBox
                                    label="Active Threats"
                                    value={
                                        device.threats
                                    }
                                    warning={
                                        device.threats
                                        > 0
                                    }
                                />


                                <InfoBox
                                    label="Last Checked"
                                    value={
                                        device.lastChecked
                                    }
                                />


                                <InfoBox
                                    label="Monitoring"
                                    value={
                                        device.monitoring
                                            ? "Active"
                                            : "Paused"
                                    }
                                    safe={
                                        device.monitoring
                                    }
                                />

                            </Box>

                        </Box>

                    </Box>


                    {/* RIGHT */}

                    <Box
                        sx={{
                            display:
                                "flex",

                            alignItems:
                                "center",

                            minWidth:
                                170,
                        }}
                    >

                        <Button
                            variant="outlined"

                            endIcon={
                                <ArrowForwardRounded />
                            }

                            onClick={
                                onView
                            }

                            fullWidth
                        >
                            View Device
                        </Button>

                    </Box>

                </Box>

            </CardContent>

        </Card>

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
                        mt:
                            0.5,

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
/* INFO BOX */
/* ================================================================ */

function InfoBox({
    label,
    value,
    warning,
    safe,
}) {

    let valueColor =
        "#f8fafc";


    if (
        warning
    ) {
        valueColor =
            "#f59e0b";
    }


    if (
        safe
    ) {
        valueColor =
            "#22c55e";
    }


    return (

        <Box
            sx={{
                p:
                    1.5,

                borderRadius:
                    "10px",

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
                        11,
                }}
            >
                {
                    label
                }
            </Typography>


            <Typography
                sx={{
                    mt:
                        0.4,

                    fontWeight:
                        600,

                    fontSize:
                        13,

                    color:
                        valueColor,
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
/* STATUS CONFIG */
/* ================================================================ */

function getStatusConfig(
    status
) {

    switch (
        status
    ) {

        case "PROTECTED":

            return {
                label:
                    "Protected",

                color:
                    "#22c55e",

                icon:
                    <CheckCircleRounded />,
            };


        case "NEEDS_ATTENTION":

            return {
                label:
                    "Needs Attention",

                color:
                    "#f59e0b",

                icon:
                    <WarningAmberRounded />,
            };


        default:

            return {
                label:
                    "Unknown",

                color:
                    "#94a3b8",

                icon:
                    <SecurityRounded />,
            };

    }

}


export default Devices;