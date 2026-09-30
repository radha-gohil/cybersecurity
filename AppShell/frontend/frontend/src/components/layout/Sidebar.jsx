import {
    Box,
    Typography,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Divider,
} from "@mui/material";

import {
    DashboardRounded,
    SecurityRounded,
    SearchRounded,
    WarningAmberRounded,
    DevicesRounded,
    PsychologyRounded,
    ScienceRounded,
    ApprovalRounded,
    HistoryRounded,
    BarChartRounded,
    SettingsRounded,
} from "@mui/icons-material";

import {
    useLocation,
    useNavigate,
} from "react-router-dom";


const menuGroups = [
    {
        label: "HOME",
        items: [
            {
                label: "Dashboard",
                path: "/",
                icon: <DashboardRounded />,
            },
        ],
    },

    {
        label: "SECURITY",
        items: [
            
            {
                label: "Live Monitor",
                path: "/live-monitor",
                icon: <SearchRounded />,
            },
            {
                label: "Threats",
                path: "/threats",
                icon: <WarningAmberRounded />,
            },
        ],
    },

    {
        label: "AI SECURITY",
        items: [
            {
                label: "AI Investigation",
                path: "/ai-security",
                icon: <PsychologyRounded />,
            },
            {
                label: "Response Simulator",
                path: "/response-simulator",
                icon: <ScienceRounded />,
            },
        ],
    },

    {
        label: "ACTION CENTER",
        items: [
            {
                label: "Approvals",
                path: "/approvals",
                icon: <ApprovalRounded />,
            },
        ],
    },

    {
        label: "HISTORY",
        items: [
            
            {
                label: "Reports",
                path: "/reports",
                icon: <BarChartRounded />,
            },
        ],
    },

    {
        label: "SYSTEM",
        items: [
            {
                label: "Settings",
                path: "/settings",
                icon: <SettingsRounded />,
            },
        ],
    },
];


function Sidebar() {

    const location =
        useLocation();

    const navigate =
        useNavigate();


    return (

        <Box
            sx={{
                width: 250,
                minWidth: 250,
                height: "100vh",
                background:
                    "#07101f",
                borderRight:
                    "1px solid #1e293b",

                display:
                    "flex",

                flexDirection:
                    "column",

                overflowY:
                    "auto",
            }}
        >

            {/* ================================================= */}
            {/* BRAND */}
            {/* ================================================= */}

            <Box
                sx={{
                    px: 3,
                    py: 3,
                }}
            >

                <Box
                    sx={{
                        display:
                            "flex",

                        alignItems:
                            "center",

                        gap: 1.3,
                    }}
                >

                    <Box
                        sx={{
                            width: 40,
                            height: 40,

                            borderRadius:
                                "12px",

                            display:
                                "flex",

                            alignItems:
                                "center",

                            justifyContent:
                                "center",

                            background:
                                "linear-gradient(135deg, #16a34a, #22c55e)",

                            fontSize: 22,
                        }}
                    >
                        🛡
                    </Box>


                    <Box>

                        <Typography
                            sx={{
                                fontWeight:
                                    800,

                                fontSize:
                                    19,

                                letterSpacing:
                                    0.5,
                            }}
                        >
                            SENTINEL-X
                        </Typography>


                        <Typography
                            sx={{
                                color:
                                    "#64748b",

                                fontSize:
                                    11,
                            }}
                        >
                            AI Security Platform
                        </Typography>

                    </Box>

                </Box>

            </Box>


            <Divider
                sx={{
                    borderColor:
                        "#1e293b",
                }}
            />


            {/* ================================================= */}
            {/* NAVIGATION */}
            {/* ================================================= */}

            <Box
                sx={{
                    px: 1.5,
                    py: 2,
                }}
            >

                {menuGroups.map(
                    (
                        group,
                        groupIndex,
                    ) => (

                        <Box
                            key={
                                group.label
                            }
                            sx={{
                                mb: 2,
                            }}
                        >

                            <Typography
                                sx={{
                                    px: 1.5,
                                    mb: 0.8,

                                    fontSize:
                                        10,

                                    fontWeight:
                                        700,

                                    color:
                                        "#64748b",

                                    letterSpacing:
                                        1.2,
                                }}
                            >
                                {
                                    group.label
                                }
                            </Typography>


                            <List
                                disablePadding
                            >

                                {group.items.map(
                                    (
                                        item,
                                    ) => {

                                        const active =
                                            location.pathname
                                            === item.path;


                                        return (

                                            <ListItemButton
                                                key={
                                                    item.path
                                                }

                                                onClick={
                                                    () =>
                                                        navigate(
                                                            item.path
                                                        )
                                                }

                                                sx={{
                                                    mb: 0.5,

                                                    borderRadius:
                                                        "10px",

                                                    color:
                                                        active
                                                            ? "#ffffff"
                                                            : "#94a3b8",

                                                    backgroundColor:
                                                        active
                                                            ? "rgba(34,197,94,0.15)"
                                                            : "transparent",

                                                    "&:hover":
                                                    {
                                                        backgroundColor:
                                                            active
                                                                ? "rgba(34,197,94,0.18)"
                                                                : "rgba(148,163,184,0.08)",
                                                    },

                                                    "&::before":
                                                    active
                                                        ? {
                                                            content:
                                                                '""',

                                                            position:
                                                                "absolute",

                                                            left:
                                                                0,

                                                            width:
                                                                3,

                                                            height:
                                                                22,

                                                            borderRadius:
                                                                "0 4px 4px 0",

                                                            background:
                                                                "#22c55e",
                                                        }
                                                        : {},
                                                }}
                                            >

                                                <ListItemIcon
                                                    sx={{
                                                        minWidth:
                                                            40,

                                                        color:
                                                            active
                                                                ? "#22c55e"
                                                                : "#64748b",
                                                    }}
                                                >
                                                    {
                                                        item.icon
                                                    }
                                                </ListItemIcon>


                                                <ListItemText
                                                    primary={
                                                        item.label
                                                    }

                                                    primaryTypographyProps={{
                                                        fontSize:
                                                            14,

                                                        fontWeight:
                                                            active
                                                                ? 600
                                                                : 500,
                                                    }}
                                                />

                                            </ListItemButton>

                                        );

                                    }
                                )}

                            </List>


                            {groupIndex
                                !==
                                menuGroups.length
                                - 1
                                && (

                                    <Divider
                                        sx={{
                                            mt: 2,

                                            borderColor:
                                                "#172033",
                                        }}
                                    />

                                )}

                        </Box>

                    )
                )}

            </Box>


            {/* ================================================= */}
            {/* BOTTOM STATUS */}
            {/* ================================================= */}

            <Box
                sx={{
                    mt: "auto",

                    p: 2,
                }}
            >

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
                            fontSize:
                                12,

                            color:
                                "#94a3b8",
                        }}
                    >
                        Protection Status
                    </Typography>


                    <Box
                        sx={{
                            mt: 1,

                            display:
                                "flex",

                            alignItems:
                                "center",

                            gap: 1,
                        }}
                    >

                        <Box
                            sx={{
                                width: 9,
                                height: 9,

                                borderRadius:
                                    "50%",

                                background:
                                    "#22c55e",

                                boxShadow:
                                    "0 0 10px #22c55e",
                            }}
                        />


                        <Typography
                            sx={{
                                fontSize:
                                    13,

                                fontWeight:
                                    600,

                                color:
                                    "#22c55e",
                            }}
                        >
                            Protection Active
                        </Typography>

                    </Box>

                </Box>

            </Box>

        </Box>

    );

}


export default Sidebar;