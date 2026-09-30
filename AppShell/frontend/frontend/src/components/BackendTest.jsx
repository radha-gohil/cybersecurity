import {
    Alert,
    Box,
    CircularProgress,
    Typography,
} from "@mui/material";

import {
    useEffect,
    useState,
} from "react";

import {
    getHealth,
} from "../api/sentinelApi";


function BackendTest() {

    const [status, setStatus] =
        useState("loading");

    const [data, setData] =
        useState(null);

    const [error, setError] =
        useState(null);


    useEffect(() => {

        async function testBackend() {

            try {

                const result =
                    await getHealth();


                console.log(
                    "SENTINEL-X HEALTH:",
                    result
                );


                setData(
                    result
                );

                setStatus(
                    "connected"
                );

            }
            catch (err) {

                console.error(
                    err
                );

                setError(
                    err.message
                );

                setStatus(
                    "error"
                );

            }

        }


        testBackend();

    }, []);


    if (
        status === "loading"
    ) {

        return (

            <Box
                sx={{
                    display: "flex",
                    gap: 1,
                    alignItems: "center",
                }}
            >

                <CircularProgress
                    size={20}
                />

                <Typography>
                    Connecting to Sentinel-X...
                </Typography>

            </Box>

        );

    }


    if (
        status === "error"
    ) {

        return (

            <Alert
                severity="error"
            >
                Backend connection failed:
                {" "}
                {error}
            </Alert>

        );

    }


    return (

        <Alert
            severity="success"
        >
            Sentinel-X backend connected successfully.
        </Alert>

    );

}


export default BackendTest;