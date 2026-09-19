import {
    BrowserRouter,
    Routes,
    Route,
} from "react-router-dom";

import Layout from "./components/Layout";

import Dashboard from "./pages/Dashboard";
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

                    <Route
                        path="/"
                        element={<Dashboard />}
                    />


                    <Route
                        path="/incidents"
                        element={<Incidents />}
                    />


                    <Route
                        path="/incidents/:incidentId"
                        element={<IncidentDetail />}
                    />


                    <Route
                        path="/tickets"
                        element={<Tickets />}
                    />


                    <Route
                        path="/approvals"
                        element={<Approvals />}
                    />


                    <Route
                        path="/responses"
                        element={<ResponseActions />}
                    />


                    <Route
                        path="/endpoint"
                        element={<Endpoint />}
                    />


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