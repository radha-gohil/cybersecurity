import {
    Box,
    Typography,
    Card,
    CardContent,
    Button,
    Chip,
    Stack,
    Divider,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
} from "@mui/material";

import {
    ApprovalRounded,
    WarningAmberRounded,
    CheckCircleRounded,
    CancelRounded,
    ShieldRounded,
    StopCircleRounded,
    LanguageRounded,
    FolderRounded,
    SettingsRounded,
    DevicesRounded,
} from "@mui/icons-material";

import {
    useState,
} from "react";


const initialActions = [
    {
        id: "ACTION-001",
        type: "TERMINATE_PROCESS",
        title: "Stop suspicious application",
        description:
            "Sentinel-X recommends stopping an application that participated in the detected threat sequence.",
        target: "PowerShell",
        impact: "LOW",
        severity: "CRITICAL",
        reason:
            "The process showed suspicious behavior and was linked to other high-risk activity.",
        effect:
            "The selected application would be stopped from running.",
        reversible: false,
        status: "PENDING",
        icon: <StopCircleRounded />,
    },

    {
        id: "ACTION-002",
        type: "QUARANTINE_FILE",
        title: "Quarantine suspicious file",
        description:
            "Sentinel-X recommends isolating a suspicious file so it cannot continue running.",
        target: "demo.exe",
        impact: "LOW",
        severity: "CRITICAL",
        reason:
            "The file was associated with suspicious process and persistence behavior.",
        effect:
            "The file would be moved to a protected quarantine location.",
        reversible: true,
        status: "PENDING",
        icon: <FolderRounded />,
    },

    {
        id: "ACTION-003",
        type: "BLOCK_NETWORK",
        title: "Block suspicious connection",
        description:
            "Sentinel-X recommends blocking communication with a suspicious external address.",
        target: "203.0.113.220",
        impact: "LOW",
        severity: "CRITICAL",
        reason:
            "The connection was associated with the detected threat sequence.",
        effect:
            "Future communication with this address would be blocked.",
        reversible: true,
        status: "PENDING",
        icon: <LanguageRounded />,
    },

    {
        id: "ACTION-004",
        type: "REMEDIATE_PERSISTENCE",
        title: "Remove suspicious startup behavior",
        description:
            "Sentinel-X recommends removing a suspicious startup configuration change.",
        target: "Windows startup configuration",
        impact: "MEDIUM",
        severity: "CRITICAL",
        reason:
            "The startup entry may allow the suspicious application to run again after restart.",
        effect:
            "The suspicious persistence configuration would be removed.",
        reversible: true,
        status: "PENDING",
        icon: <SettingsRounded />,
    },

    {
        id: "ACTION-005",
        type: "ISOLATE_ENDPOINT",
        title: "Disconnect device from network",
        description:
            "Sentinel-X can isolate this device if stronger containment becomes necessary.",
        target: "Personal Laptop",
        impact: "HIGH",
        severity: "CRITICAL",
        reason:
            "Isolation can prevent suspicious activity from communicating with other systems.",
        effect:
            "The device would temporarily lose normal network communication.",
        reversible: true,
        status: "PENDING",
        icon: <DevicesRounded />,
    },
];


function Approvals() {

    const [actions, setActions] =
        useState(
            initialActions
        );

    const [selectedAction, setSelectedAction] =
        useState(null);

    const [dialogMode, setDialogMode] =
        useState(null);


    const pendingCount =
        actions.filter(
            (action) =>
                action.status
                === "PENDING"
        ).length;


    const approvedCount =
        actions.filter(
            (action) =>
                action.status
                === "APPROVED"
        ).length;


    const rejectedCount =
        actions.filter(
            (action) =>
                action.status
                === "REJECTED"
        ).length;


    const openDialog = (
        action,
        mode
    ) => {

        setSelectedAction(
            action
        );

        setDialogMode(
            mode
        );

    };


    const closeDialog = () => {

        setSelectedAction(
            null
        );

        setDialogMode(
            null
        );

    };


    const confirmDecision = () => {

        if (
            !selectedAction
            ||
            !dialogMode
        ) {
            return;
        }


        setActions(
            (previous) =>
                previous.map(
                    (action) => {

                        if (
                            action.id
                            !== selectedAction.id
                        ) {
                            return action;
                        }


                        return {
                            ...action,

                            status:
                                dialogMode
                                === "APPROVE"
                                    ? "APPROVED"
                                    : "REJECTED",
                        };

                    }
                )
        );


        closeDialog();

    };


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
                    Approvals
                </Typography>


                <Typography
                    sx={{
                        color:
                            "#94a3b8",

                        mt:
                            0.5,
                    }}
                >
                    Review Sentinel-X protection actions before
                    anything important is allowed to proceed.
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
                            xs:
                                "1fr",

                            sm:
                                "repeat(3, 1fr)",
                        },

                    gap:
                        2,

                    mb:
                        3,
                }}
            >

                <SummaryCard
                    title="Needs Your Review"
                    value={
                        pendingCount
                    }
                    color="#f59e0b"
                />

                <SummaryCard
                    title="Approved"
                    value={
                        approvedCount
                    }
                    color="#22c55e"
                />

                <SummaryCard
                    title="Rejected"
                    value={
                        rejectedCount
                    }
                    color="#ef4444"
                />

            </Box>


            {/* ================================================= */}
            {/* SAFETY BANNER */}
            {/* ================================================= */}

            <Card
                sx={{
                    mb:
                        3,

                    borderColor:
                        "rgba(59,130,246,0.25)",
                }}
            >

                <CardContent
                    sx={{
                        p:
                            2.5,

                        display:
                            "flex",

                        alignItems:
                            "center",

                        gap:
                            2,
                    }}
                >

                    <ShieldRounded
                        sx={{
                            color:
                                "#3b82f6",
                        }}
                    />


                    <Box>

                        <Typography
                            sx={{
                                fontWeight:
                                    600,
                            }}
                        >
                            Simulation Mode Active
                        </Typography>


                        <Typography
                            sx={{
                                color:
                                    "#64748b",

                                fontSize:
                                    13,

                                mt:
                                    0.3,
                            }}
                        >
                            Approving an action in this prototype
                            does not modify your real device.
                            Sentinel-X keeps response execution
                            simulated.
                        </Typography>

                    </Box>

                </CardContent>

            </Card>


            {/* ================================================= */}
            {/* ACTION CARDS */}
            {/* ================================================= */}

            <Stack
                spacing={
                    2
                }
            >

                {
                    actions.map(
                        (
                            action,
                        ) => (

                            <ApprovalCard
                                key={
                                    action.id
                                }

                                action={
                                    action
                                }

                                onApprove={
                                    () =>
                                        openDialog(
                                            action,
                                            "APPROVE"
                                        )
                                }

                                onReject={
                                    () =>
                                        openDialog(
                                            action,
                                            "REJECT"
                                        )
                                }
                            />

                        )
                    )
                }

            </Stack>


            {/* ================================================= */}
            {/* CONFIRMATION DIALOG */}
            {/* ================================================= */}

            <Dialog
                open={
                    Boolean(
                        selectedAction
                    )
                }

                onClose={
                    closeDialog
                }

                fullWidth

                maxWidth="sm"

                PaperProps={{
                    sx: {
                        background:
                            "#111827",

                        backgroundImage:
                            "none",

                        border:
                            "1px solid #1e293b",
                    },
                }}
            >

                {
                    selectedAction
                    && (

                        <>

                            <DialogTitle>

                                {
                                    dialogMode
                                    === "APPROVE"
                                        ? "Approve protection action?"
                                        : "Reject protection action?"
                                }

                            </DialogTitle>


                            <DialogContent>

                                <Typography
                                    sx={{
                                        fontWeight:
                                            700,

                                        fontSize:
                                            17,

                                        mb:
                                            1,
                                    }}
                                >
                                    {
                                        selectedAction.title
                                    }
                                </Typography>


                                <Typography
                                    sx={{
                                        color:
                                            "#94a3b8",

                                        mb:
                                            2,
                                    }}
                                >
                                    {
                                        selectedAction.description
                                    }
                                </Typography>


                                <Box
                                    sx={{
                                        p:
                                            2,

                                        borderRadius:
                                            "12px",

                                        background:
                                            "#0f172a",

                                        border:
                                            "1px solid #1e293b",
                                    }}
                                >

                                    <DialogInfo
                                        label="Target"
                                        value={
                                            selectedAction.target
                                        }
                                    />

                                    <DialogInfo
                                        label="Impact"
                                        value={
                                            selectedAction.impact
                                        }
                                    />

                                    <DialogInfo
                                        label="What will change"
                                        value={
                                            selectedAction.effect
                                        }
                                    />

                                    <DialogInfo
                                        label="Can it be undone?"
                                        value={
                                            selectedAction.reversible
                                                ? "Yes"
                                                : "Not automatically"
                                        }
                                    />

                                </Box>


                                {
                                    dialogMode
                                    === "APPROVE"
                                    && (

                                        <Typography
                                            sx={{
                                                mt:
                                                    2,

                                                color:
                                                    "#94a3b8",

                                                fontSize:
                                                    13,
                                            }}
                                        >
                                            This approval will only
                                            mark the action as approved
                                            in the current frontend
                                            simulation.
                                        </Typography>

                                    )
                                }

                            </DialogContent>


                            <DialogActions>

                                <Button
                                    onClick={
                                        closeDialog
                                    }
                                >
                                    Cancel
                                </Button>


                                <Button
                                    variant="contained"

                                    color={
                                        dialogMode
                                        === "APPROVE"
                                            ? "success"
                                            : "error"
                                    }

                                    onClick={
                                        confirmDecision
                                    }
                                >
                                    {
                                        dialogMode
                                        === "APPROVE"
                                            ? "Approve"
                                            : "Reject"
                                    }
                                </Button>

                            </DialogActions>

                        </>

                    )
                }

            </Dialog>

        </Box>

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
                    p:
                        2.5,
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
                        fontSize:
                            30,

                        fontWeight:
                            800,

                        mt:
                            0.5,

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
/* APPROVAL CARD */
/* ================================================================ */

function ApprovalCard({
    action,
    onApprove,
    onReject,
}) {

    const statusConfig =
        getStatusConfig(
            action.status
        );


    const impactColor =
        getImpactColor(
            action.impact
        );


    return (

        <Card
            sx={{
                borderColor:
                    action.status
                    === "PENDING"
                        ? "rgba(245,158,11,0.25)"
                        : "#1e293b",
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

                        gap:
                            3,

                        flexWrap:
                            "wrap",
                    }}
                >

                    {/* LEFT */}

                    <Box
                        sx={{
                            display:
                                "flex",

                            gap:
                                2,

                            flex:
                                1,

                            minWidth:
                                280,
                        }}
                    >

                        <Box
                            sx={{
                                width:
                                    50,

                                height:
                                    50,

                                minWidth:
                                    50,

                                borderRadius:
                                    "14px",

                                display:
                                    "flex",

                                alignItems:
                                    "center",

                                justifyContent:
                                    "center",

                                color:
                                    action.status
                                    === "PENDING"
                                        ? "#f59e0b"
                                        : statusConfig.color,

                                background:
                                    action.status
                                    === "PENDING"
                                        ? "rgba(245,158,11,0.10)"
                                        : `${statusConfig.color}12`,
                            }}
                        >

                            {
                                action.icon
                            }

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

                                    mb:
                                        0.7,
                                }}
                            >

                                <Typography
                                    sx={{
                                        fontSize:
                                            18,

                                        fontWeight:
                                            700,
                                    }}
                                >
                                    {
                                        action.title
                                    }
                                </Typography>


                                <Chip
                                    label={
                                        action.severity
                                    }

                                    size="small"

                                    sx={{
                                        color:
                                            "#ef4444",

                                        background:
                                            "rgba(239,68,68,0.10)",
                                    }}
                                />

                            </Box>


                            <Typography
                                sx={{
                                    color:
                                        "#94a3b8",

                                    fontSize:
                                        13,

                                    maxWidth:
                                        760,
                                }}
                            >
                                {
                                    action.description
                                }
                            </Typography>


                            <Box
                                sx={{
                                    display:
                                        "grid",

                                    gridTemplateColumns:
                                        {
                                            xs:
                                                "1fr",

                                            md:
                                                "repeat(3, 1fr)",
                                        },

                                    gap:
                                        1.5,

                                    mt:
                                        2,
                                }}
                            >

                                <InfoBox
                                    label="Target"
                                    value={
                                        action.target
                                    }
                                />

                                <InfoBox
                                    label="Impact"
                                    value={
                                        action.impact
                                    }
                                    color={
                                        impactColor
                                    }
                                />

                                <InfoBox
                                    label="Reversible"
                                    value={
                                        action.reversible
                                            ? "Yes"
                                            : "Limited"
                                    }
                                />

                            </Box>


                            <Box
                                sx={{
                                    mt:
                                        2,

                                    p:
                                        1.5,

                                    borderRadius:
                                        "10px",

                                    background:
                                        "#0f172a",
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
                                    Why Sentinel-X recommends this
                                </Typography>


                                <Typography
                                    sx={{
                                        color:
                                            "#cbd5e1",

                                        fontSize:
                                            13,

                                        mt:
                                            0.4,
                                    }}
                                >
                                    {
                                        action.reason
                                    }
                                </Typography>

                            </Box>

                        </Box>

                    </Box>


                    {/* RIGHT */}

                    <Box
                        sx={{
                            minWidth:
                                180,

                            display:
                                "flex",

                            flexDirection:
                                "column",

                            alignItems:
                                {
                                    xs:
                                        "stretch",

                                    md:
                                        "flex-end",
                                },

                            gap:
                                1.5,
                        }}
                    >

                        <Chip
                            label={
                                statusConfig.label
                            }

                            sx={{
                                color:
                                    statusConfig.color,

                                background:
                                    `${statusConfig.color}12`,

                                border:
                                    `1px solid ${statusConfig.color}30`,

                                fontWeight:
                                    700,
                            }}
                        />


                        {
                            action.status
                            === "PENDING"
                            && (

                                <Stack
                                    direction="row"
                                    spacing={
                                        1
                                    }
                                >

                                    <Button
                                        variant="outlined"

                                        color="error"

                                        startIcon={
                                            <CancelRounded />
                                        }

                                        onClick={
                                            onReject
                                        }
                                    >
                                        Reject
                                    </Button>


                                    <Button
                                        variant="contained"

                                        color="success"

                                        startIcon={
                                            <CheckCircleRounded />
                                        }

                                        onClick={
                                            onApprove
                                        }
                                    >
                                        Approve
                                    </Button>

                                </Stack>

                            )
                        }

                    </Box>

                </Box>

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
    color,
}) {

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
                        color
                        || "#f8fafc",
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
/* DIALOG INFO */
/* ================================================================ */

function DialogInfo({
    label,
    value,
}) {

    return (

        <Box
            sx={{
                py:
                    0.8,
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
                    fontSize:
                        13,

                    fontWeight:
                        600,

                    mt:
                        0.2,
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

        case "APPROVED":

            return {
                label:
                    "Approved",

                color:
                    "#22c55e",
            };


        case "REJECTED":

            return {
                label:
                    "Rejected",

                color:
                    "#ef4444",
            };


        default:

            return {
                label:
                    "Needs Approval",

                color:
                    "#f59e0b",
            };

    }

}


/* ================================================================ */
/* IMPACT COLOR */
/* ================================================================ */

function getImpactColor(
    impact
) {

    switch (
        impact
    ) {

        case "HIGH":
            return "#ef4444";

        case "MEDIUM":
            return "#f59e0b";

        case "LOW":
            return "#22c55e";

        default:
            return "#94a3b8";

    }

}


export default Approvals;