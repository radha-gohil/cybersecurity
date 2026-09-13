from typing import Dict, List


class ProcessAnalyzer:

    def __init__(self):

        # --------------------------------------------------------
        # WINDOWS UTILITIES THAT CAN BE ABUSED BY ATTACKERS
        # --------------------------------------------------------
        # These programs are NOT malicious by default.
        # We only increase risk when they are used in suspicious context.

        self.lolbins = {
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
        # PARENT PROCESSES THAT MAY BE SUSPICIOUS
        # --------------------------------------------------------

        self.suspicious_parents = {
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
        }

        # --------------------------------------------------------
        # SUSPICIOUS COMMAND-LINE PATTERNS
        # --------------------------------------------------------

        self.command_keywords = [
            "-encodedcommand",
            "-enc ",
            "invoke-webrequest",
            "invoke-expression",
            "iex ",
            "downloadstring",
            "frombase64string",
            "certutil",
            "bitsadmin",
            "http://",
            "https://",
        ]

        # --------------------------------------------------------
        # SUSPICIOUS EXECUTION LOCATIONS
        # --------------------------------------------------------

        self.suspicious_paths = [
            "\\appdata\\local\\temp\\",
            "\\temp\\",
            "\\downloads\\",
        ]


    # ============================================================
    # MAIN ANALYSIS FUNCTION
    # ============================================================

    def analyze(
        self,
        process: Dict,
    ) -> Dict:

        risk_score = 0

        reasons: List[str] = []


        # --------------------------------------------------------
        # GET PROCESS INFORMATION
        # --------------------------------------------------------

        process_name = (
            process.get("name") or ""
        ).lower()

        parent_name = (
            process.get("parent_name") or ""
        ).lower()

        command_line = (
            process.get("command_line") or ""
        ).lower()

        path = (
            process.get("path") or ""
        ).lower()


        # ========================================================
        # RULE 1
        # WINDOWS UTILITY EXECUTION
        # ========================================================

        if process_name in self.lolbins:

            risk_score += 15

            reasons.append(
                f"Sensitive Windows utility executed: {process_name}"
            )


        # ========================================================
        # RULE 2
        # OFFICE APPLICATION SPAWNING COMMAND INTERPRETER
        # ========================================================

        suspicious_children = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
        }


        if (
            parent_name in self.suspicious_parents
            and
            process_name in suspicious_children
        ):

            risk_score += 40

            reasons.append(
                f"Suspicious parent-child relationship: "
                f"{parent_name} -> {process_name}"
            )


        # ========================================================
        # RULE 3
        # SUSPICIOUS COMMAND-LINE KEYWORDS
        # ========================================================

        matched_keywords = []


        for keyword in self.command_keywords:

            if keyword in command_line:

                matched_keywords.append(
                    keyword
                )


        if matched_keywords:

            keyword_risk = (
                len(matched_keywords) * 15
            )

            risk_score += keyword_risk


            for keyword in matched_keywords:

                reasons.append(
                    f"Suspicious command-line keyword detected: {keyword}"
                )


        # ========================================================
        # RULE 4
        # EXECUTABLE RUNNING FROM SUSPICIOUS DIRECTORY
        # ========================================================

        if any(
            suspicious_path in path
            for suspicious_path in self.suspicious_paths
        ):

            risk_score += 20

            reasons.append(
                "Process executed from a temporary or download directory"
            )


        # ========================================================
        # RULE 5
        # POWERSHELL WITH ENCODED COMMAND
        # ========================================================

        if (
            process_name in {
                "powershell.exe",
                "pwsh.exe",
            }
            and
            (
                "-encodedcommand" in command_line
                or
                "-enc " in command_line
            )
        ):

            risk_score += 30

            reasons.append(
                "PowerShell executed an encoded command"
            )


        # ========================================================
        # RULE 6
        # POWERSHELL DOWNLOADING CONTENT
        # ========================================================

        if (
            process_name in {
                "powershell.exe",
                "pwsh.exe",
            }
            and
            (
                "invoke-webrequest" in command_line
                or
                "downloadstring" in command_line
            )
        ):

            risk_score += 25

            reasons.append(
                "PowerShell command appears to download remote content"
            )


        # ========================================================
        # LIMIT SCORE TO 100
        # ========================================================

        risk_score = min(
            risk_score,
            100
        )


        # ========================================================
        # DETERMINE SEVERITY
        # ========================================================

        if risk_score >= 80:

            severity = "CRITICAL"

        elif risk_score >= 60:

            severity = "HIGH"

        elif risk_score >= 30:

            severity = "MEDIUM"

        elif risk_score > 0:

            severity = "LOW"

        else:

            severity = "INFO"


        # ========================================================
        # DETECTION DECISION
        # ========================================================

        detected = (
            risk_score >= 30
        )


        if detected:

            threat_type = "SUSPICIOUS"

        else:

            threat_type = "BENIGN"


        # ========================================================
        # CONFIDENCE
        # ========================================================

        confidence = round(
            risk_score / 100,
            2
        )


        # ========================================================
        # RETURN STANDARD DETECTION FORMAT
        # ========================================================

        return {

            "engine":
                "process_behavior_engine",

            "detected":
                detected,

            "threat_type":
                threat_type,

            "confidence":
                confidence,

            "risk_score":
                risk_score,

            "severity":
                severity,

            "reason":
                reasons,

        }