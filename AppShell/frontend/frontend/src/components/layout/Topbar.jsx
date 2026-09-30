import {
    Box,
    Typography,
    IconButton,
    Badge,
    Avatar,
    Tooltip,
} from "@mui/material";

import {
    NotificationsNoneRounded,
    HelpOutlineRounded,
} from "@mui/icons-material";


function Topbar() {

    return (

        <Box
            sx={{
                height: 72,

                px: 3,

                display:
                    "flex",

                alignItems:
                    "center",

                justifyContent:
                    "space-between",

                borderBottom:
                    "1px solid #1e293b",

                background:
                    "#0b1120",
            }}
        >

            {/* ================================================= */}
            {/* LEFT */}
            {/* ================================================= */}

            <Box>

                <Typography
                    sx={{
                        fontSize:
                            13,

                        color:
                            "#64748b",
                    }}
                >
                    Sentinel-X Security Center
                </Typography>


                <Typography
                    sx={{
                        fontSize:
                            16,

                        fontWeight:
                            600,
                    }}
                >
                    System Protection
                </Typography>

            </Box>


            {/* ================================================= */}
            {/* RIGHT */}
            {/* ================================================= */}

            <Box
                sx={{
                    display:
                        "flex",

                    alignItems:
                        "center",

                    gap: 1.5,
                }}
            >

                {/* Protection Status */}

                <Box
                    sx={{
                        px: 2,
                        py: 0.8,

                        borderRadius:
                            "20px",

                        display:
                            "flex",

                        alignItems:
                            "center",

                        gap: 1,

                        background:
                            "rgba(34,197,94,0.10)",

                        border:
                            "1px solid rgba(34,197,94,0.25)",
                    }}
                >

                    <Box
                        sx={{
                            width: 8,
                            height: 8,

                            borderRadius:
                                "50%",

                            background:
                                "#22c55e",
                        }}
                    />


                    <Typography
                        sx={{
                            fontSize:
                                12,

                            fontWeight:
                                600,

                            color:
                                "#22c55e",
                        }}
                    >
                        Protected
                    </Typography>

                </Box>


                <Tooltip
                    title="Help"
                >

                    <IconButton
                        sx={{
                            color:
                                "#94a3b8",
                        }}
                    >
                        <HelpOutlineRounded />
                    </IconButton>

                </Tooltip>


                <Tooltip
                    title="Notifications"
                >

                    <IconButton
                        sx={{
                            color:
                                "#94a3b8",
                        }}
                    >

                        <Badge
                            badgeContent={
                                2
                            }

                            color="error"
                        >
                            <NotificationsNoneRounded />
                        </Badge>

                    </IconButton>

                </Tooltip>


                <Avatar
                    sx={{
                        width: 36,
                        height: 36,

                        background:
                            "#16a34a",

                        fontSize:
                            14,

                        fontWeight:
                            700,
                    }}
                >
                    SX
                </Avatar>

            </Box>

        </Box>

    );

}


export default Topbar;