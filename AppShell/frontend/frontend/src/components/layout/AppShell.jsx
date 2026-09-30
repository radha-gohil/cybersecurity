import {
    Box,
} from "@mui/material";

import {
    Outlet,
} from "react-router-dom";

import Sidebar from "./Sidebar";
import Topbar from "./Topbar";


function AppShell() {

    return (

        <Box
            sx={{
                display:
                    "flex",

                height:
                    "100vh",

                background:
                    "#0b1120",

                overflow:
                    "hidden",
            }}
        >

            {/* ================================================= */}
            {/* SIDEBAR */}
            {/* ================================================= */}

            <Sidebar />


            {/* ================================================= */}
            {/* MAIN APPLICATION */}
            {/* ================================================= */}

            <Box
                sx={{
                    flex: 1,

                    display:
                        "flex",

                    flexDirection:
                        "column",

                    minWidth:
                        0,
                }}
            >

                <Topbar />


                {/* ============================================= */}
                {/* PAGE CONTENT */}
                {/* ============================================= */}

                <Box
                    component="main"

                    sx={{
                        flex: 1,

                        overflowY:
                            "auto",

                        p: 3,

                        background:
                            "#0b1120",
                    }}
                >

                    <Outlet />

                </Box>

            </Box>

        </Box>

    );

}


export default AppShell;