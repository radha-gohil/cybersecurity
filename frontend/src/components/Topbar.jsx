import {
    useEffect,
    useState,
} from "react";

import {
    getHealth,
} from "../api/sentinelApi";


function Topbar() {

    const [
        backendStatus,
        setBackendStatus,
    ] = useState(
        "CHECKING"
    );


    const [
        simulationMode,
        setSimulationMode,
    ] = useState(true);


    useEffect(() => {

        let active = true;


        const checkBackend =
            async () => {

                try {

                    const data =
                        await getHealth();


                    if (!active) {
                        return;
                    }


                    if (
                        data?.status
                        === "HEALTHY"
                    ) {

                        setBackendStatus(
                            "CONNECTED"
                        );

                    } else {

                        setBackendStatus(
                            "DISCONNECTED"
                        );
                    }


                    setSimulationMode(
                        data
                            ?.simulation_mode
                        !== false
                    );

                } catch (error) {

                    console.error(
                        "Backend health check failed:",
                        error
                    );


                    if (active) {

                        setBackendStatus(
                            "DISCONNECTED"
                        );
                    }
                }
            };


        checkBackend();


        const interval =
            setInterval(
                checkBackend,
                10000
            );


        return () => {

            active = false;

            clearInterval(
                interval
            );
        };

    }, []);


    let statusClass =
        "topbar-status checking";


    if (
        backendStatus
        === "CONNECTED"
    ) {

        statusClass =
            "topbar-status connected";

    } else if (
        backendStatus
        === "DISCONNECTED"
    ) {

        statusClass =
            "topbar-status disconnected";
    }


    return (

        <header className="topbar">

            <div>

                <h1>
                    Security Operations Center
                </h1>


                <p>
                    Autonomous incident intelligence
                    and response decision support
                </p>

            </div>


            <div className="topbar-right">

                {
                    simulationMode
                    && (

                    <div className="topbar-simulation">

                        SIMULATION MODE

                    </div>
                )}


                <div className={statusClass}>

                    <span className="status-dot" />


                    <span>

                        {
                            backendStatus
                            === "CONNECTED"
                                ? "Backend Connected"

                            : backendStatus
                            === "DISCONNECTED"
                                ? "Backend Disconnected"

                            : "Checking Backend..."
                        }

                    </span>

                </div>

            </div>

        </header>
    );
}


export default Topbar;