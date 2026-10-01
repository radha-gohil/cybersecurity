import {
    Box,
    Card,
    CardContent,
    Typography,
    Chip,
    Alert,
    CircularProgress,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
} from "@mui/material";

import {
    useEffect,
    useRef,
    useState,
} from "react";

import {
    getLiveDetections,
} from "../api/sentinelApi";


const SEVERITY_COLORS = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#f59e0b",
    LOW: "#22c55e",
    INFO: "#3b82f6",
};


function displayValue(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "—";
    }

    return String(value);
}


function formatTimestamp(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return displayValue(value);
    }

    return date.toLocaleString();
}


function formatNumber(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "—";
    }

    const number = Number(value);

    if (!Number.isFinite(number)) {
        return displayValue(value);
    }

    return number.toLocaleString(
        undefined,
        {
            maximumFractionDigits: 3,
        }
    );
}


function SeverityChip({ severity }) {
    const label = severity
        ? String(severity).toUpperCase()
        : "UNKNOWN";

    const color =
        SEVERITY_COLORS[label] || "#94a3b8";

    return (
        <Chip
            label={label}
            size="small"
            sx={{
                color,
                fontWeight: 700,
                background: `${color}15`,
                border: `1px solid ${color}35`,
            }}
        />
    );
}


function SecurityDetectionFeed() {

    const [detections, setDetections] =
        useState([]);

    const [totalStored, setTotalStored] =
        useState(0);

    const [loading, setLoading] =
        useState(true);

    const [error, setError] =
        useState(null);

    const [lastUpdated, setLastUpdated] =
        useState(null);

    const requestInProgress = useRef(false);

    useEffect(() => {

        let active = true;

        async function refreshDetections() {

            if (requestInProgress.current) {
                return;
            }

            requestInProgress.current = true;

            try {

                const response =
                    await getLiveDetections(50);

                if (!active) {
                    return;
                }

                const records = Array.isArray(
                    response?.detections
                )
                    ? response.detections
                    : [];

                // De-duplicate rows returned by polling.
                // This affects display only, not the database.

                const seen = new Set();

                const uniqueRecords = records.filter(
                    (record, index) => {

                        const identity = (
                            record.detection_id != null
                                ? `id:${record.detection_id}`
                                : JSON.stringify([
                                    record.event_id,
                                    record.timestamp,
                                    record.engine,
                                    record.threat_type,
                                    record.severity,
                                    index,
                                ])
                        );

                        if (seen.has(identity)) {
                            return false;
                        }

                        seen.add(identity);
                        return true;
                    }
                );

                setDetections(uniqueRecords);

                setTotalStored(
                    Number(
                        response?.total_stored_detections
                        ?? 0
                    )
                );

                setLastUpdated(new Date());
                setError(null);

            } catch (err) {

                if (active) {

                    setError(
                        err?.response?.data?.detail ||
                        err?.message ||
                        "Unable to load security detections."
                    );
                }

            } finally {

                requestInProgress.current = false;

                if (active) {
                    setLoading(false);
                }
            }
        }

        refreshDetections();

        const interval = setInterval(
            refreshDetections,
            5000
        );

        return () => {
            active = false;
            clearInterval(interval);
        };

    }, []);


    return (
        <Card sx={{ mt: 3 }}>

            <CardContent sx={{ p: 3 }}>

                <Box
                    sx={{
                        display: "flex",
                        justifyContent:
                            "space-between",
                        alignItems: "center",
                        flexWrap: "wrap",
                        gap: 2,
                        mb: 2,
                    }}
                >

                    <Box>

                        <Typography variant="h6">
                            Security Detection Feed
                        </Typography>

                        <Typography
                            sx={{
                                color: "#64748b",
                                fontSize: 13,
                                mt: 0.5,
                            }}
                        >
                            Recent stored security detections.
                            Updated every 5 seconds.
                        </Typography>

                    </Box>

                    <Chip
                        label={`Stored detections: ${totalStored.toLocaleString()}`}
                        size="small"
                        sx={{
                            color: "#22c55e",
                            background:
                                "rgba(34,197,94,0.10)",
                            fontWeight: 700,
                        }}
                    />

                </Box>


                {error && (
                    <Alert
                        severity="error"
                        sx={{ mb: 2 }}
                    >
                        {error}
                    </Alert>
                )}


                {loading ? (

                    <Box
                        sx={{
                            display: "flex",
                            justifyContent: "center",
                            p: 4,
                        }}
                    >
                        <CircularProgress />
                    </Box>

                ) : detections.length === 0 ? (

                    <Alert severity="info">
                        No detection records are available
                        in the recent database results.
                    </Alert>

                ) : (

                    <TableContainer
                        sx={{
                            overflowX: "auto",
                        }}
                    >

                        <Table
                            size="small"
                            sx={{
                                minWidth: 900,
                            }}
                        >

                            <TableHead>

                                <TableRow>

                                    {[
                                        "Timestamp",
                                        "Source",
                                        "Detection Engine",
                                        "Threat Type",
                                        "Severity",
                                        "Confidence",
                                        "Risk Score",
                                        "Incident ID",
                                    ].map((heading) => (

                                        <TableCell
                                            key={heading}
                                            sx={{
                                                color: "#94a3b8",
                                                fontWeight: 700,
                                                whiteSpace: "nowrap",
                                            }}
                                        >
                                            {heading}
                                        </TableCell>

                                    ))}

                                </TableRow>

                            </TableHead>


                            <TableBody>

                                {detections.map(
                                    (detection, index) => (

                                        <TableRow
                                            key={
                                                detection.detection_id
                                                ?? `${detection.event_id}-${index}`
                                            }
                                            hover
                                        >

                                            <TableCell>
                                                {formatTimestamp(
                                                    detection.timestamp
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                {displayValue(
                                                    detection.source
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                {displayValue(
                                                    detection.engine
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                {displayValue(
                                                    detection.threat_type
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                <SeverityChip
                                                    severity={
                                                        detection.severity
                                                    }
                                                />
                                            </TableCell>

                                            <TableCell>
                                                {formatNumber(
                                                    detection.confidence
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                {formatNumber(
                                                    detection.risk_score
                                                )}
                                            </TableCell>

                                            <TableCell>
                                                {displayValue(
                                                    detection.incident_id
                                                )}
                                            </TableCell>

                                        </TableRow>
                                    )
                                )}

                            </TableBody>

                        </Table>

                    </TableContainer>
                )}


                {lastUpdated && (

                    <Typography
                        sx={{
                            color: "#64748b",
                            fontSize: 12,
                            mt: 2,
                        }}
                    >
                        Last updated:{" "}
                        {lastUpdated.toLocaleTimeString()}
                    </Typography>
                )}

            </CardContent>

        </Card>
    );
}


export default SecurityDetectionFeed;