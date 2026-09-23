import {
    BrowserRouter,
    Routes,
    Route,
} from "react-router-dom";

import Layout from "./components/Layout";

import Dashboard from "./pages/Dashboard";
import SOCDashboard from "./pages/SOCDashboard";

import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Tickets from "./pages/Tickets";
import Approvals from "./pages/Approvals";
import ResponseActions from "./pages/ResponseActions";
import Endpoint from "./pages/Endpoint";
import SystemHealth from "./pages/SystemHealth";


function App() {

    return (

        <BrowserRouter>

            <Routes>

                <Route
                    element={<Layout />}
                >

                    {/* =========================================
                        EXISTING DASHBOARD
                    ========================================== */}

                    <Route
                        path="/"
                        element={<Dashboard />}
                    />


                    {/* =========================================
                        NEW SENTINEL-X SOC DASHBOARD
                    ========================================== */}

                    <Route
                        path="/soc"
                        element={<SOCDashboard />}
                    />


                    {/* =========================================
                        INCIDENTS
                    ========================================== */}

                    <Route
                        path="/incidents"
                        element={<Incidents />}
                    />


                    <Route
                        path="/incidents/:incidentId"
                        element={<IncidentDetail />}
                    />


                    {/* =========================================
                        SOC TICKETS
                    ========================================== */}

                    <Route
                        path="/tickets"
                        element={<Tickets />}
                    />


                    {/* =========================================
                        ANALYST APPROVALS
                    ========================================== */}

                    <Route
                        path="/approvals"
                        element={<Approvals />}
                    />


                    {/* =========================================
                        RESPONSE ACTIONS
                    ========================================== */}

                    <Route
                        path="/responses"
                        element={<ResponseActions />}
                    />


                    {/* =========================================
                        ENDPOINT MONITORING
                    ========================================== */}

                    <Route
                        path="/endpoint"
                        element={<Endpoint />}
                    />


                    {/* =========================================
                        SYSTEM HEALTH
                    ========================================== */}

                    <Route
                        path="/health"
                        element={<SystemHealth />}
                    />

                </Route>

            </Routes>

        </BrowserRouter>
    );
}


export default App;