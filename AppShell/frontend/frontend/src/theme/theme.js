import { createTheme } from "@mui/material/styles";

const theme = createTheme({
    palette: {
        mode: "dark",

        background: {
            default: "#0b1120",
            paper: "#111827",
        },

        primary: {
            main: "#22c55e",
        },

        success: {
            main: "#22c55e",
        },

        warning: {
            main: "#f59e0b",
        },

        error: {
            main: "#ef4444",
        },

        info: {
            main: "#3b82f6",
        },

        text: {
            primary: "#f8fafc",
            secondary: "#94a3b8",
        },
    },

    typography: {
        fontFamily:
            '"Inter", "Segoe UI", "Roboto", "Arial", sans-serif',

        h4: {
            fontWeight: 700,
        },

        h5: {
            fontWeight: 700,
        },

        h6: {
            fontWeight: 600,
        },

        button: {
            textTransform: "none",
            fontWeight: 600,
        },
    },

    shape: {
        borderRadius: 14,
    },

    components: {
        MuiCard: {
            styleOverrides: {
                root: {
                    backgroundImage: "none",
                    border: "1px solid #1e293b",
                },
            },
        },

        MuiButton: {
            styleOverrides: {
                root: {
                    borderRadius: 10,
                    paddingLeft: 18,
                    paddingRight: 18,
                },
            },
        },
    },
});

export default theme;