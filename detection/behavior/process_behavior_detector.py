from pathlib import Path


class ProcessBehaviorDetector:

    def __init__(self):

        # --------------------------------------------------------
        # Windows binaries that are legitimate but are commonly
        # relevant during security investigations.
        # Their presence alone does NOT mean malicious activity.
        # --------------------------------------------------------

        self.monitored_binaries = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
        }


        # --------------------------------------------------------
        # Command-line characteristics worth investigating.
        # --------------------------------------------------------

        self.command_indicators = {
            "-encodedcommand":
                30,

            "-enc":
                30,

            "-windowstyle hidden":
                15,

            "-w hidden":
                15,

            "invoke-webrequest":
                10,

            "invoke-restmethod":
                10,

            "downloadstring":
                20,

            "frombase64string":
                20,
        }


        # --------------------------------------------------------
        # Parent applications that normally should not frequently
        # launch scripting interpreters.
        # --------------------------------------------------------

        self.document_parents = {
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
        }


        self.script_children = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        }


    # ============================================================
    # NORMALIZE TEXT
    # ============================================================

    def normalize(
        self,
        value,
    ) -> str:

        if value is None:
            return ""

        if isinstance(
            value,
            list,
        ):

            value = " ".join(
                str(item)
                for item in value
            )

        return str(
            value
        ).strip().lower()


    # ============================================================
    # EXTRACT EXECUTABLE NAME
    # ============================================================

    def get_executable_name(
        self,
        value,
    ) -> str:

        value = self.normalize(
            value
        )

        if not value:
            return ""

        try:

            return Path(
                value
            ).name.lower()

        except Exception:

            return value


    # ============================================================
    # CONVERT SCORE TO SEVERITY
    # ============================================================

    def score_to_severity(
        self,
        score: int,
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 35:
            return "MEDIUM"

        if score >= 15:
            return "LOW"

        return "INFO"


    # ============================================================
    # ANALYZE PROCESS BEHAVIOR
    # ============================================================

    def analyze(
        self,
        process: dict,
    ) -> dict:

        score = 0

        reasons = []

        indicators = []


        # --------------------------------------------------------
        # SUPPORT MULTIPLE POSSIBLE FIELD NAMES
        # --------------------------------------------------------

        process_name = self.get_executable_name(
            process.get(
                "name"
            )
            or process.get(
                "process_name"
            )
            or process.get(
                "exe"
            )
        )


        process_path = self.normalize(
            process.get(
                "exe"
            )
            or process.get(
                "path"
            )
            or process.get(
                "process_path"
            )
        )


        command_line = self.normalize(
            process.get(
                "cmdline"
            )
            or process.get(
                "command_line"
            )
            or process.get(
                "command"
            )
        )


        parent_name = self.get_executable_name(
            process.get(
                "parent_name"
            )
            or process.get(
                "parent_process"
            )
            or process.get(
                "pprocess_name"
            )
        )


        # --------------------------------------------------------
        # CHECK MONITORED SYSTEM BINARIES
        # --------------------------------------------------------

        if (
            process_name
            in self.monitored_binaries
        ):

            score += 5

            reasons.append(
                "Security-relevant Windows utility observed"
            )

            indicators.append(
                "monitored_binary"
            )


        # --------------------------------------------------------
        # COMMAND-LINE INDICATORS
        # --------------------------------------------------------

        for (
            indicator,
            indicator_score,
        ) in self.command_indicators.items():

            if (
                indicator
                in command_line
            ):

                score += (
                    indicator_score
                )

                reasons.append(
                    f"Command-line indicator observed: "
                    f"{indicator}"
                )

                indicators.append(
                    f"command:{indicator}"
                )


        # --------------------------------------------------------
        # DOCUMENT APPLICATION SPAWNING SCRIPT ENGINE
        # --------------------------------------------------------

        if (
            parent_name
            in self.document_parents
            and process_name
            in self.script_children
        ):

            score += 40

            reasons.append(
                "Document application launched "
                "a scripting or command interpreter"
            )

            indicators.append(
                "document_to_script"
            )


        # --------------------------------------------------------
        # TEMP DIRECTORY EXECUTION
        # --------------------------------------------------------

        temp_locations = (
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\temp\\",
        )


        if any(
            location
            in process_path
            for location
            in temp_locations
        ):

            score += 15

            reasons.append(
                "Process executed from a temporary directory"
            )

            indicators.append(
                "temp_execution"
            )


        # --------------------------------------------------------
        # SCRIPT ENGINE WITH NETWORK-RELATED COMMAND LINE
        # --------------------------------------------------------

        network_terms = (
            "http://",
            "https://",
        )


        if (
            process_name
            in self.script_children
            and any(
                term
                in command_line
                for term
                in network_terms
            )
        ):

            score += 15

            reasons.append(
                "Script or command interpreter contains "
                "a network URL in its command line"
            )

            indicators.append(
                "script_network_reference"
            )


        # --------------------------------------------------------
        # CAP SCORE
        # --------------------------------------------------------

        score = min(
            score,
            100,
        )


        severity = (
            self.score_to_severity(
                score
            )
        )


        suspicious = (
            score >= 35
        )


        return {

            "behavior_score":
                score,

            "severity":
                severity,

            "suspicious":
                suspicious,

            "reasons":
                reasons,

            "indicators":
                indicators,

            "process_name":
                process_name,

            "parent_name":
                parent_name,
        }