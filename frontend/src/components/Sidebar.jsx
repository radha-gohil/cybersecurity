import {
    NavLink,
} from "react-router-dom";


const menuItems = [

    {
        name: "SOC Dashboard",
        path: "/soc",
    },

    {
        name: "SOC Overview",
        path: "/",
    },

    {
        name: "Incidents",
        path: "/incidents",
    },

    {
        name: "Tickets",
        path: "/tickets",
    },

    {
        name: "Approvals",
        path: "/approvals",
    },

    {
        name: "Response Actions",
        path: "/responses",
    },

    {
        name: "Endpoint",
        path: "/endpoint",
    },

    {
        name: "System Health",
        path: "/health",
    },

];


function Sidebar() {

    return (

        <aside className="sidebar">

            {/* =========================================
                BRAND
            ========================================== */}

            <div className="sidebar-brand">

                <h2>
                    SENTINEL-X
                </h2>

                <p>
                    Autonomous Security Operations
                </p>

            </div>


            {/* =========================================
                NAVIGATION
            ========================================== */}

            <nav className="sidebar-nav">

                {
                    menuItems.map(
                        (item) => (

                            <NavLink
                                key={
                                    item.path
                                }

                                to={
                                    item.path
                                }

                                end={
                                    item.path === "/"
                                }

                                className={
                                    ({
                                        isActive,
                                    }) =>
                                        isActive
                                            ? "nav-link active"
                                            : "nav-link"
                                }
                            >

                                {
                                    item.name
                                }

                            </NavLink>

                        )
                    )
                }

            </nav>


            {/* =========================================
                SAFETY / AUTONOMY STATUS
            ========================================== */}

            <div className="sidebar-footer">

                <strong>
                    SIMULATION MODE
                </strong>

                <small>
                    Real response execution
                    disabled
                </small>

            </div>

        </aside>
    );
}


export default Sidebar;