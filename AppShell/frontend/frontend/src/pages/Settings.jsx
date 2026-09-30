import {
    Box,
    Typography,
    Card,
    CardContent,
    Switch,
    Divider,
    Select,
    MenuItem,
    FormControl,
    Button,
    Stack,
    Chip,
} from "@mui/material";

import {
    SettingsRounded,
    NotificationsRounded,
    SecurityRounded,
    ScheduleRounded,
    DarkModeRounded,
    CloudUploadRounded,
    RestartAltRounded,
} from "@mui/icons-material";

import {
    useState,
} from "react";


function Settings() {

    const [realTimeProtection, setRealTimeProtection] =
        useState(true);

    const [processMonitoring, setProcessMonitoring] =
        useState(true);

    const [fileMonitoring, setFileMonitoring] =
        useState(true);

    const [networkMonitoring, setNetworkMonitoring] =
        useState(true);

    const [registryMonitoring, setRegistryMonitoring] =
        useState(true);

    const [criticalAlerts, setCriticalAlerts] =
        useState(true);

    const [investigationAlerts, setInvestigationAlerts] =
        useState(true);

    const [approvalAlerts, setApprovalAlerts] =
        useState(true);

    const [shareTelemetry, setShareTelemetry] =
        useState(false);

    const [askBeforeMetadata, setAskBeforeMetadata] =
        useState(true);

    const [automaticScan, setAutomaticScan] =
        useState(true);

    const [themeMode, setThemeMode] =
        useState("dark");

    const [scanDay, setScanDay] =
        useState("Sunday");


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
                    Settings
                </Typography>


                <Typography
                    sx={{
                        color: "#94a3b8",
                        mt: 0.5,
                    }}
                >
                    Manage Sentinel-X protection, notifications,
                    privacy and application preferences.
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* PROTECTION SETTINGS */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <SecurityRounded />
                }
                title="Protection"
                description="Control how Sentinel-X monitors this PC."
            >

                <SettingToggle
                    title="Real-time protection"
                    description="Continuously monitor this PC for suspicious activity."
                    checked={
                        realTimeProtection
                    }
                    onChange={
                        setRealTimeProtection
                    }
                    important
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="Process monitoring"
                    description="Watch running applications for suspicious behavior."
                    checked={
                        processMonitoring
                    }
                    onChange={
                        setProcessMonitoring
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="File monitoring"
                    description="Watch important file activity and suspicious changes."
                    checked={
                        fileMonitoring
                    }
                    onChange={
                        setFileMonitoring
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="Network monitoring"
                    description="Analyze network connections for suspicious communication."
                    checked={
                        networkMonitoring
                    }
                    onChange={
                        setNetworkMonitoring
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="System protection"
                    description="Monitor important Windows configuration and startup activity."
                    checked={
                        registryMonitoring
                    }
                    onChange={
                        setRegistryMonitoring
                    }
                />

            </SettingsSection>


            {/* ================================================= */}
            {/* SCAN SETTINGS */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <ScheduleRounded />
                }
                title="Scans"
                description="Configure automatic protection scans."
            >

                <SettingToggle
                    title="Automatic quick scan"
                    description="Run a quick security scan automatically each week."
                    checked={
                        automaticScan
                    }
                    onChange={
                        setAutomaticScan
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <Box
                    sx={{
                        px: 3,
                        py: 2.5,

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
                                fontWeight: 600,
                            }}
                        >
                            Weekly scan day
                        </Typography>


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 12,
                                mt: 0.4,
                            }}
                        >
                            Choose when the automatic quick scan runs.
                        </Typography>

                    </Box>


                    <FormControl
                        size="small"
                        sx={{
                            minWidth: 150,
                        }}
                    >

                        <Select
                            value={
                                scanDay
                            }
                            onChange={
                                (event) =>
                                    setScanDay(
                                        event.target.value
                                    )
                            }
                        >

                            <MenuItem value="Monday">
                                Monday
                            </MenuItem>

                            <MenuItem value="Tuesday">
                                Tuesday
                            </MenuItem>

                            <MenuItem value="Wednesday">
                                Wednesday
                            </MenuItem>

                            <MenuItem value="Thursday">
                                Thursday
                            </MenuItem>

                            <MenuItem value="Friday">
                                Friday
                            </MenuItem>

                            <MenuItem value="Saturday">
                                Saturday
                            </MenuItem>

                            <MenuItem value="Sunday">
                                Sunday
                            </MenuItem>

                        </Select>

                    </FormControl>

                </Box>

            </SettingsSection>


            {/* ================================================= */}
            {/* NOTIFICATIONS */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <NotificationsRounded />
                }
                title="Notifications"
                description="Choose which Sentinel-X alerts appear."
            >

                <SettingToggle
                    title="Critical threat alerts"
                    description="Notify me immediately when a critical threat is detected."
                    checked={
                        criticalAlerts
                    }
                    onChange={
                        setCriticalAlerts
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="AI investigation completed"
                    description="Notify me when Sentinel-X finishes investigating a threat."
                    checked={
                        investigationAlerts
                    }
                    onChange={
                        setInvestigationAlerts
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="Approval required"
                    description="Notify me when an important protection action requires review."
                    checked={
                        approvalAlerts
                    }
                    onChange={
                        setApprovalAlerts
                    }
                />

            </SettingsSection>


            {/* ================================================= */}
            {/* PRIVACY */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <CloudUploadRounded />
                }
                title="Privacy"
                description="Control what security information Sentinel-X may share."
            >

                <SettingToggle
                    title="Share anonymous security telemetry"
                    description="Allow anonymous security statistics to be used for improving threat detection."
                    checked={
                        shareTelemetry
                    }
                    onChange={
                        setShareTelemetry
                    }
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <SettingToggle
                    title="Ask before sharing file metadata"
                    description="Request confirmation before suspicious file metadata is shared."
                    checked={
                        askBeforeMetadata
                    }
                    onChange={
                        setAskBeforeMetadata
                    }
                />


                <Box
                    sx={{
                        px: 3,
                        pb: 2.5,
                    }}
                >

                    <Chip
                        label="No file contents uploaded automatically"
                        size="small"
                        sx={{
                            color: "#3b82f6",
                            background:
                                "rgba(59,130,246,0.10)",
                        }}
                    />

                </Box>

            </SettingsSection>


            {/* ================================================= */}
            {/* APPEARANCE */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <DarkModeRounded />
                }
                title="Appearance"
                description="Customize the Sentinel-X interface."
            >

                <Box
                    sx={{
                        px: 3,
                        py: 2.5,

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
                                fontWeight: 600,
                            }}
                        >
                            Theme
                        </Typography>


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 12,
                                mt: 0.4,
                            }}
                        >
                            Choose the Sentinel-X application appearance.
                        </Typography>

                    </Box>


                    <FormControl
                        size="small"
                        sx={{
                            minWidth: 140,
                        }}
                    >

                        <Select
                            value={
                                themeMode
                            }
                            onChange={
                                (event) =>
                                    setThemeMode(
                                        event.target.value
                                    )
                            }
                        >

                            <MenuItem value="dark">
                                Dark
                            </MenuItem>

                            <MenuItem value="light">
                                Light
                            </MenuItem>

                            <MenuItem value="system">
                                System
                            </MenuItem>

                        </Select>

                    </FormControl>

                </Box>

            </SettingsSection>


            {/* ================================================= */}
            {/* RESPONSE MODE */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <SettingsRounded />
                }
                title="Response Mode"
                description="Current protection-action behavior."
            >

                <Box
                    sx={{
                        px: 3,
                        py: 2.5,

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
                                fontWeight: 600,
                            }}
                        >
                            Simulation Mode
                        </Typography>


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 12,
                                mt: 0.4,
                                maxWidth: 650,
                            }}
                        >
                            Sentinel-X evaluates and simulates response
                            actions without making real endpoint changes.
                        </Typography>

                    </Box>


                    <Chip
                        label="ACTIVE"
                        sx={{
                            color: "#3b82f6",
                            background:
                                "rgba(59,130,246,0.10)",
                            fontWeight: 700,
                        }}
                    />

                </Box>

            </SettingsSection>


            {/* ================================================= */}
            {/* ADVANCED */}
            {/* ================================================= */}

            <SettingsSection
                icon={
                    <RestartAltRounded />
                }
                title="Advanced"
                description="Technical options for Sentinel-X."
            >

                <AdvancedRow
                    title="Detection engines"
                    description="View the status of Sentinel-X detection components."
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <AdvancedRow
                    title="System health"
                    description="View backend and protection-service status."
                />


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                <AdvancedRow
                    title="Audit information"
                    description="Review important security decision history."
                />

            </SettingsSection>

        </Box>

    );

}


/* ================================================================ */
/* SETTINGS SECTION */
/* ================================================================ */

function SettingsSection({
    icon,
    title,
    description,
    children,
}) {

    return (

        <Card
            sx={{
                mb: 3,
            }}
        >

            <CardContent
                sx={{
                    p: 0,
                }}
            >

                <Box
                    sx={{
                        px: 3,
                        py: 2.5,

                        display: "flex",
                        alignItems: "center",
                        gap: 1.5,
                    }}
                >

                    <Box
                        sx={{
                            width: 42,
                            height: 42,

                            borderRadius: "12px",

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
                            variant="h6"
                        >
                            {title}
                        </Typography>


                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 12,
                                mt: 0.2,
                            }}
                        >
                            {description}
                        </Typography>

                    </Box>

                </Box>


                <Divider
                    sx={{
                        borderColor: "#1e293b",
                    }}
                />


                {children}

            </CardContent>

        </Card>

    );

}


/* ================================================================ */
/* SETTING TOGGLE */
/* ================================================================ */

function SettingToggle({
    title,
    description,
    checked,
    onChange,
    important,
}) {

    return (

        <Box
            sx={{
                px: 3,
                py: 2.5,

                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 3,
            }}
        >

            <Box>

                <Box
                    sx={{
                        display: "flex",
                        alignItems: "center",
                        gap: 1,
                    }}
                >

                    <Typography
                        sx={{
                            fontWeight: 600,
                        }}
                    >
                        {title}
                    </Typography>


                    {
                        important
                        && (

                            <Chip
                                label="Recommended"
                                size="small"
                                sx={{
                                    color: "#22c55e",
                                    background:
                                        "rgba(34,197,94,0.10)",
                                }}
                            />

                        )
                    }

                </Box>


                <Typography
                    sx={{
                        color: "#64748b",
                        fontSize: 12,
                        mt: 0.4,
                        maxWidth: 700,
                    }}
                >
                    {description}
                </Typography>

            </Box>


            <Switch
                checked={
                    checked
                }
                color="success"
                onChange={
                    (event) =>
                        onChange(
                            event.target.checked
                        )
                }
            />

        </Box>

    );

}


/* ================================================================ */
/* ADVANCED ROW */
/* ================================================================ */

function AdvancedRow({
    title,
    description,
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


            <Button>
                View
            </Button>

        </Box>

    );

}


export default Settings;