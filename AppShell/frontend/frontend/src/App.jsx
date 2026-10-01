import {
    Routes,
    Route,
} from "react-router-dom";

import {
    Box,
    Typography,
} from "@mui/material";

import AppShell from "./components/layout/AppShell";
import Dashboard from "./pages/Dashboard";
import Protection from "./pages/Protection";
import ScanCenter from "./pages/ScanCenter";
import Threats from "./pages/Threats";
import ThreatDetail from "./pages/ThreatDetail";
import AISecurity from "./pages/AISecurity";
import ResponseSimulator from "./pages/ResponseSimulator";
import Approvals from "./pages/Approvals";
import Activity from "./pages/Activity";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";
import LiveMonitor from "./pages/LiveMonitor";

function PlaceholderPage({
    title,
}) {

    return (

        <Box>

            <Typography
                variant="h4"
            >
                {
                    title
                }
            </Typography>


            <Typography
                sx={{
                    color:
                        "#94a3b8",

                    mt: 1,
                }}
            >
                This Sentinel-X module will be built next.
            </Typography>

        </Box>

    );

}


function App() {

    return (

        <Routes>

            <Route
                element={
                    <AppShell />
                }
            >

                <Route
                    path="/"
                    element={
                        <Dashboard />
                    }
                />


                <Route
                    path="/protection"
                    element={
                        <Protection />
                    }
                />


                <Route
                    path="/live-monitor"
                    element={
                        <LiveMonitor />
                    }
                />

                


                <Route
                    path="/threats"
                    element={
                        <Threats />
                    }
                />

                <Route
                    path="/threats/:threatId"
                    element={
                        <ThreatDetail />
                    }
                />


                

                <Route
                    path="/ai-security"
                    element={
                        <AISecurity />
                    }
                />


                <Route
                    path="/response-simulator"
                    element={
                        <ResponseSimulator />
                    }
                />


                <Route
                    path="/approvals"
                    element={
                        <Approvals />
                    }
                />


                <Route
                    path="/activity"
                    element={
                        <Activity />
                    }
                />


                <Route
                    path="/reports"
                    element={
                        <Reports />
                    }
                />


                <Route
                    path="/settings"
                    element={
                        <Settings />
                    }
                />

            </Route>

        </Routes>

    );

}


export default App;