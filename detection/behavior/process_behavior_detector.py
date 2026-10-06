from pathlib import Path


class ProcessBehaviorDetector:

    def __init__(self):

        # ========================================================
        # MONITORED WINDOWS BINARIES
        # ========================================================

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


        # ========================================================
        # GENERIC COMMAND INDICATORS
        # ========================================================

        self.command_indicators = {

            # Encoded PowerShell
            "-encodedcommand": 30,
            "-encoded-command": 30,

            # IMPORTANT:
            # trailing space prevents matching
            # "-EncodedCommand" as "-enc"
            "-enc ": 30,


            # Hidden PowerShell
            "-windowstyle hidden": 15,
            "-window hidden": 15,
            "-w hidden": 15,


            # Download / network behavior
            "invoke-webrequest": 10,
            "invoke-restmethod": 10,
            "downloadstring": 20,
            "frombase64string": 20,


            # Downloaded/script execution
            "invoke-expression": 30,
            "iex ": 30,
        }


        # ========================================================
        # DOCUMENT PARENTS
        # ========================================================

        self.document_parents = {
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
        }


        # ========================================================
        # SCRIPT CHILDREN
        # ========================================================

        self.script_children = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        }


    # ============================================================
    # NORMALIZE
    # ============================================================

    def normalize(
        self,
        value,
    ) -> str:

        if value is None:
            return ""

        if isinstance(
            value,
            (
                list,
                tuple,
            ),
        ):

            value = " ".join(
                str(item)
                for item in value
            )

        return str(
            value
        ).strip().lower()


    # ============================================================
    # EXECUTABLE NAME
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

        value = value.replace(
            "/",
            "\\",
        )

        try:

            return (
                value
                .rsplit(
                    "\\",
                    1,
                )[-1]
                .lower()
            )

        except Exception:

            return value


    # ============================================================
    # SEVERITY
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
    # ANALYZE
    # ============================================================

    def analyze(
        self,
        process: dict,
    ) -> dict:

        if not isinstance(
            process,
            dict,
        ):

            process = {}


        score = 0

        reasons = []

        indicators = []


        # ========================================================
        # PROCESS INFORMATION
        # ========================================================

        process_name = (
            self.get_executable_name(

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
        )


        process_path = (
            self.normalize(

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
        )


        command_line = (
            self.normalize(

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
        )


        parent_name = (
            self.get_executable_name(

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
        )


        # ========================================================
        # MONITORED SYSTEM BINARY
        # ========================================================

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


        # ========================================================
        # GENERIC COMMAND-LINE INDICATORS
        # ========================================================

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
                    "Command-line indicator observed: "
                    f"{indicator}"
                )

                indicators.append(
                    f"command:{indicator}"
                )


        # ========================================================
        # DOCUMENT APPLICATION → SCRIPT ENGINE
        # ========================================================

        if (
            parent_name
            in self.document_parents

            and

            process_name
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


        # ========================================================
        # TEMP DIRECTORY EXECUTION
        # ========================================================

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


        # ========================================================
        # NETWORK URL
        # ========================================================

        has_network_url = any(

            marker
            in command_line

            for marker
            in (
                "http://",
                "https://",
            )
        )


        # ========================================================
        # GENERIC SCRIPT ENGINE + URL
        # ========================================================

        if (
            process_name
            in self.script_children

            and

            has_network_url
        ):

            score += 15

            reasons.append(
                "Script or command interpreter contains "
                "a network URL in its command line"
            )

            indicators.append(
                "script_network_reference"
            )


        # ========================================================
        # REMOTE WSCRIPT / CSCRIPT / MSHTA
        #
        # 5 monitored
        # +15 URL
        # +55 remote script execution
        # =75
        # ========================================================

        if (
            process_name
            in {
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
            }

            and

            has_network_url
        ):

            score += 55

            reasons.append(
                "Windows script interpreter is executing "
                "remote network content"
            )

            indicators.append(
                "remote_script_execution"
            )


        # ========================================================
        # CERTUTIL DOWNLOAD
        # ========================================================

        if (
            process_name
            == "certutil.exe"

            and

            has_network_url

            and

            "-urlcache"
            in command_line
        ):

            score += 70

            reasons.append(
                "CertUtil remote URL-cache download behavior"
            )

            indicators.append(
                "certutil_remote_download"
            )


        # ========================================================
        # BITSADMIN TRANSFER
        # ========================================================

        if (
            process_name
            == "bitsadmin.exe"

            and

            has_network_url

            and

            "/transfer"
            in command_line
        ):

            score += 70

            reasons.append(
                "BITSAdmin remote transfer behavior"
            )

            indicators.append(
                "bitsadmin_remote_transfer"
            )


        # ========================================================
        # RUNDLL32 SCRIPT EXECUTION
        # ========================================================

        if (
            process_name
            == "rundll32.exe"

            and

            any(

                marker
                in command_line

                for marker
                in (
                    "javascript:",
                    "vbscript:",
                    "mshtml,runhtmlapplication",
                )
            )
        ):

            score += 70

            reasons.append(
                "Rundll32 script-based execution behavior"
            )

            indicators.append(
                "rundll32_script_execution"
            )


        # ========================================================
        # REGSVR32 REMOTE SCRIPTLET
        # ========================================================

        if (
            process_name
            == "regsvr32.exe"

            and

            has_network_url

            and

            "/i:"
            in command_line

            and

            "scrobj.dll"
            in command_line
        ):

            score += 70

            reasons.append(
                "Regsvr32 remote scriptlet execution behavior"
            )

            indicators.append(
                "regsvr32_remote_scriptlet"
            )


        # ========================================================
        # FINAL SCORE
        # ========================================================

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