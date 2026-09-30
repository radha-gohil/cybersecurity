import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Grid,
    Switch,
    Chip,
    Stack,
    Divider,
} from "@mui/material";

import {
    SecurityRounded,
    SearchRounded,
    ShieldRounded,
    FolderRounded,
    LanguageRounded,
    SettingsApplicationsRounded,
    PsychologyRounded,
    CheckCircleRounded,
    ChevronRightRounded,
} from "@mui/icons-material";

import { useNavigate } from "react-router-dom";


const protectionModules = [
    {
        title: "Process Protection",
        description:
            "Monitors running applications for suspicious behavior.",
        icon: <SettingsApplicationsRounded />,
        enabled: true,
    },
    {
        title: "File Protection",
        description:
            "Checks files and file activity for potentially unsafe behavior.",
        icon: <FolderRounded />,
        enabled: true,
    },
    {
        title: "Network Protection",
        description:
            "Monitors network connections for suspicious communication.",
        icon: <LanguageRounded />,
        enabled: true,
    },
    {
        title: "System Protection",
        description:
            "Monitors important Windows configuration and persistence activity.",
        icon: <ShieldRounded />,
        enabled: true,
    },
];


function Protection() {

    const navigate = useNavigate();


    return (

        <Box>

            {/* ================================================= */}
            {/* PAGE HEADER */}
            {/* ================================================= */}

            <Box sx={{ mb: 3 }}>

                <Typography variant="h4">
                    Protection
                </Typography>

                <Typography
                    sx={{
                        color: "#94a3b8",
                        mt: 0.5,
                    }}
                >
                    Manage how Sentinel-X protects your device.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* MAIN PROTECTION STATUS */}
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
                            alignItems: "center",
                            justifyContent: "space-between",
                            gap: 3,
                            flexWrap: "wrap",
                        }}
                    >

                        <Box
                            sx={{
                                display: "flex",
                                alignItems: "center",
                                gap: 2,
                            }}
                        >

                            <Box
                                sx={{
                                    width: 68,
                                    height: 68,
                                    borderRadius: "18px",

                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",

                                    background:
                                        "rgba(34,197,94,0.12)",
                                }}
                            >

                                <SecurityRounded
                                    sx={{
                                        fontSize: 40,
                                        color: "#22c55e",
                                    }}
                                />

                            </Box>


                            <Box>

                                <Typography
                                    variant="h5"
                                    sx={{
                                        mb: 0.5,
                                    }}
                                >
                                    Your protection is active
                                </Typography>

                                <Typography
                                    sx={{
                                        color: "#94a3b8",
                                        maxWidth: 600,
                                    }}
                                >
                                    Sentinel-X is monitoring your
                                    device for suspicious process,
                                    file, network, and system activity.
                                </Typography>


                                <Box
                                    sx={{
                                        display: "flex",
                                        alignItems: "center",
                                        gap: 1,
                                        mt: 1.5,
                                    }}
                                >

                                    <CheckCircleRounded
                                        sx={{
                                            color: "#22c55e",
                                            fontSize: 18,
                                        }}
                                    />

                                    <Typography
                                        sx={{
                                            color: "#22c55e",
                                            fontSize: 13,
                                            fontWeight: 600,
                                        }}
                                    >
                                        All protection modules running
                                    </Typography>

                                </Box>

                            </Box>

                        </Box>


                        <Button
                            variant="contained"
                            startIcon={
                                <SearchRounded />
                            }
                            onClick={() =>
                                navigate("/scan")
                            }
                            sx={{
                                background: "#22c55e",
                                color: "#04120a",

                                "&:hover": {
                                    background: "#16a34a",
                                },
                            }}
                        >
                            Run Security Scan
                        </Button>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* QUICK ACTIONS */}
            {/* ================================================= */}

            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                Quick Actions
            </Typography>


            <Grid
                container
                spacing={2}
                sx={{
                    mb: 4,
                }}
            >

                <Grid
                    item
                    xs={12}
                    md={4}
                >

                    <QuickActionCard
                        title="Quick Scan"
                        description="Check common threat locations."
                        icon={<SearchRounded />}
                        button="Start Scan"
                        onClick={() =>
                            navigate("/scan")
                        }
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    md={4}
                >

                    <QuickActionCard
                        title="Full Scan"
                        description="Scan your complete device."
                        icon={<SecurityRounded />}
                        button="Start Full Scan"
                        onClick={() =>
                            navigate("/scan")
                        }
                    />

                </Grid>


                <Grid
                    item
                    xs={12}
                    md={4}
                >

                    <QuickActionCard
                        title="Custom Scan"
                        description="Choose specific files or folders."
                        icon={<FolderRounded />}
                        button="Choose Location"
                        onClick={() =>
                            navigate("/scan")
                        }
                    />

                </Grid>

            </Grid>


            {/* ================================================= */}
            {/* REAL-TIME PROTECTION */}
            {/* ================================================= */}

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 2,
                }}
            >

                <Box>

                    <Typography variant="h6">
                        Real-Time Protection
                    </Typography>

                    <Typography
                        sx={{
                            color: "#64748b",
                            fontSize: 13,
                            mt: 0.4,
                        }}
                    >
                        Protection modules currently monitoring
                        your device.
                    </Typography>

                </Box>


                <Chip
                    label="ALL ACTIVE"
                    size="small"
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


            <Grid
                container
                spacing={2}
                sx={{
                    mb: 4,
                }}
            >

                {protectionModules.map(
                    (module) => (

                        <Grid
                            item
                            xs={12}
                            md={6}
                            key={module.title}
                        >

                            <ProtectionModule
                                {...module}
                            />

                        </Grid>

                    )
                )}

            </Grid>


            {/* ================================================= */}
            {/* AI PROTECTION */}
            {/* ================================================= */}

            <Typography
                variant="h6"
                sx={{
                    mb: 2,
                }}
            >
                AI Protection
            </Typography>


            <Card>

                <CardContent
                    sx={{
                        p: 0,
                    }}
                >

                    <AIProtectionRow
                        title="Smart Threat Detection"
                        description="Combines multiple detection engines to identify suspicious behavior."
                        status="Active"
                    />

                    <Divider
                        sx={{
                            borderColor: "#1e293b",
                        }}
                    />

                    <AIProtectionRow
                        title="Behavior Analysis"
                        description="Looks for unusual behavior over time."
                        status="Active"
                    />

                    <Divider
                        sx={{
                            borderColor: "#1e293b",
                        }}
                    />

                    <AIProtectionRow
                        title="Anomaly Detection"
                        description="Identifies activity that differs from normal system behavior."
                        status="Active"
                    />

                    <Divider
                        sx={{
                            borderColor: "#1e293b",
                        }}
                    />

                    <AIProtectionRow
                        title="AI Investigation"
                        description="Automatically investigates threats using Sentinel-X security agents."
                        status="Ready"
                    />

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* ADVANCED */}
            {/* ================================================= */}

            <Card
                sx={{
                    mt: 3,
                }}
            >

                <CardContent
                    sx={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 2,
                    }}
                >

                    <Box>

                        <Typography
                            sx={{
                                fontWeight: 600,
                            }}
                        >
                            Advanced Protection Details
                        </Typography>

                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 13,
                                mt: 0.4,
                            }}
                        >
                            View detection engines, monitoring
                            status and technical information.
                        </Typography>

                    </Box>


                    <Button
                        endIcon={
                            <ChevronRightRounded />
                        }
                        sx={{
                            color: "#94a3b8",
                        }}
                    >
                        View Details
                    </Button>

                </CardContent>

            </Card>

        </Box>

    );

}


/* ================================================================ */
/* QUICK ACTION CARD */
/* ================================================================ */

function QuickActionCard({
    title,
    description,
    icon,
    button,
    onClick,
}) {

    return (

        <Card
            sx={{
                height: "100%",
            }}
        >

            <CardContent
                sx={{
                    p: 3,
                }}
            >

                <Box
                    sx={{
                        width: 46,
                        height: 46,

                        borderRadius: "12px",

                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",

                        color: "#3b82f6",

                        background:
                            "rgba(59,130,246,0.10)",

                        mb: 2,
                    }}
                >
                    {icon}
                </Box>


                <Typography
                    sx={{
                        fontSize: 17,
                        fontWeight: 700,
                    }}
                >
                    {title}
                </Typography>


                <Typography
                    sx={{
                        color: "#64748b",
                        fontSize: 13,
                        mt: 0.7,
                        minHeight: 40,
                    }}
                >
                    {description}
                </Typography>


                <Button
                    onClick={onClick}
                    sx={{
                        mt: 2,
                        px: 0,
                    }}
                >
                    {button}
                </Button>

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* PROTECTION MODULE */
/* ================================================================ */

function ProtectionModule({
    title,
    description,
    icon,
    enabled,
}) {

    return (

        <Card>

            <CardContent
                sx={{
                    p: 2.5,

                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 2,
                }}
            >

                <Box
                    sx={{
                        display: "flex",
                        alignItems: "center",
                        gap: 2,
                    }}
                >

                    <Box
                        sx={{
                            width: 44,
                            height: 44,

                            borderRadius: "12px",

                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",

                            color: "#22c55e",

                            background:
                                "rgba(34,197,94,0.10)",
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
                                mt: 0.4,
                            }}
                        >
                            {description}
                        </Typography>

                    </Box>

                </Box>


                <Switch
                    checked={enabled}
                    color="success"
                />

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* AI PROTECTION ROW */
/* ================================================================ */

function AIProtectionRow({
    title,
    description,
    status,
}) {

    return (

        <Box
            sx={{
                px: 3,
                py: 2.5,

                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 2,
            }}
        >

            <Stack
                direction="row"
                spacing={2}
                alignItems="center"
            >

                <PsychologyRounded
                    sx={{
                        color: "#8b5cf6",
                    }}
                />


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

            </Stack>


            <Chip
                label={status}
                size="small"
                sx={{
                    color: "#22c55e",
                    background:
                        "rgba(34,197,94,0.10)",
                }}
            />

        </Box>

    );

}


export default Protection;