from __future__ import annotations

import math

from datetime import (
    datetime,
    timezone,
)

from pathlib import (
    PurePath,
)

from typing import (
    Any,
    Dict,
    Mapping,
)


from ai_detection.behavior.process_feature_schema import (
    PROCESS_FEATURE_SCHEMA_VERSION,
    ProcessBehaviorFeatures,
    ProcessFeatureRecord,
)


# ================================================================
# PROCESS CATEGORIES
# ================================================================

SCRIPT_INTERPRETERS = {

    "powershell.exe",
    "powershell",
    "pwsh.exe",
    "pwsh",

    "cmd.exe",
    "cmd",

    "wscript.exe",
    "wscript",

    "cscript.exe",
    "cscript",

    "mshta.exe",
    "mshta",

    "python.exe",
    "python",

    "python3.exe",
    "python3",

    "bash.exe",
    "bash",

    "sh.exe",
    "sh",
}


OFFICE_APPLICATIONS = {

    "winword.exe",
    "winword",

    "excel.exe",
    "excel",

    "powerpnt.exe",
    "powerpnt",

    "outlook.exe",
    "outlook",

    "onenote.exe",
    "onenote",

    "msaccess.exe",
    "msaccess",
}


# ================================================================
# COMMAND-LINE INDICATORS
#
# These are features only.
# Presence does NOT automatically mean malicious.
# ================================================================

ENCODED_COMMAND_KEYWORDS = (

    "-encodedcommand",
    "-encoded-command",
    "-enc ",
    "frombase64string",
)


HIDDEN_EXECUTION_KEYWORDS = (

    "-windowstyle hidden",
    "-window hidden",
    "-w hidden",
    "windowstyle hidden",
)


DOWNLOAD_KEYWORDS = (

    "invoke-webrequest",
    "invoke-restmethod",

    "start-bitstransfer",

    "bitsadmin",

    "certutil -urlcache",

    "curl ",
    "curl.exe",

    "wget ",
    "wget.exe",
)


NETWORK_TOOL_KEYWORDS = (

    "test-netconnection",

    "netcat",
    "ncat",

    "psexec",

    "telnet",

    "ssh ",

    "nslookup",
)


# ================================================================
# PATH INDICATORS
# ================================================================

TEMP_PATH_MARKERS = (

    "\\temp\\",
    "/temp/",

    "\\tmp\\",
    "/tmp/",

    "\\appdata\\local\\temp\\",

    "%temp%",
)


USER_PROFILE_MARKERS = (

    "\\users\\",

    "\\appdata\\",

    "\\downloads\\",

    "\\desktop\\",

    "\\documents\\",
)


SYSTEM_PATH_MARKERS = (

    "\\windows\\system32\\",

    "\\windows\\syswow64\\",

    "\\program files\\",

    "\\program files (x86)\\",
)


# ================================================================
# SAFE CONVERSION HELPERS
# ================================================================

def safe_float(
    value: Any,
    default: float = 0.0,
) -> float:

    if value is None:

        return default


    try:

        number = float(
            value
        )


        if not math.isfinite(
            number
        ):

            return default


        return number


    except (
        TypeError,
        ValueError,
    ):

        return default


def safe_int(
    value: Any,
    default: int | None = None,
) -> int | None:

    if value is None:

        return default


    try:

        return int(
            value
        )


    except (
        TypeError,
        ValueError,
    ):

        return default


# ================================================================
# GET FIRST AVAILABLE FIELD
#
# This allows the extractor to support different telemetry naming
# conventions without changing the AI feature schema.
# ================================================================

def first_value(
    data: Mapping[
        str,
        Any,
    ],
    *keys: str,
    default: Any = None,
) -> Any:

    for key in keys:

        if key not in data:

            continue


        value = data.get(
            key
        )


        if value is not None:

            return value


    return default


# ================================================================
# COMMAND-LINE NORMALIZATION
# ================================================================

def normalize_command_line(
    value: Any,
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

        return " ".join(
            str(
                item
            )

            for item
            in value
        )


    return str(
        value
    )


def command_argument_count(
    raw_command_line: Any,
) -> int:

    if raw_command_line is None:

        return 0


    if isinstance(
        raw_command_line,
        (
            list,
            tuple,
        ),
    ):

        return len(
            raw_command_line
        )


    command_line = str(
        raw_command_line
    ).strip()


    if not command_line:

        return 0


    # ------------------------------------------------------------
    # Lightweight count.
    #
    # We intentionally avoid shell parsing because Windows command
    # syntax varies between PowerShell, CMD, Python, etc.
    # ------------------------------------------------------------

    return len(
        command_line.split()
    )


# ================================================================
# TEXT INDICATOR
# ================================================================

def contains_any(
    text: str,
    keywords,
) -> bool:

    normalized = (
        text
        .lower()
    )


    return any(

        keyword.lower()
        in normalized

        for keyword
        in keywords
    )


# ================================================================
# PATH DEPTH
# ================================================================

def calculate_path_depth(
    executable_path: str,
) -> int:

    if not executable_path:

        return 0


    normalized = (

        executable_path
        .replace(
            "/",
            "\\",
        )
    )


    parts = [

        part

        for part
        in normalized.split(
            "\\"
        )

        if part.strip()
    ]


    return len(
        parts
    )


# ================================================================
# PROCESS AGE
# ================================================================

def calculate_process_age_seconds(
    create_time: Any,
) -> float:

    if create_time is None:

        return 0.0


    now = datetime.now(
        timezone.utc
    )


    # ------------------------------------------------------------
    # UNIX TIMESTAMP
    # ------------------------------------------------------------

    if isinstance(
        create_time,
        (
            int,
            float,
        ),
    ):

        try:

            created = (
                datetime.fromtimestamp(
                    float(
                        create_time
                    ),
                    tz=timezone.utc,
                )
            )


            return max(
                0.0,
                (
                    now
                    - created
                ).total_seconds(),
            )


        except (
            ValueError,
            OverflowError,
            OSError,
        ):

            return 0.0


    # ------------------------------------------------------------
    # ISO TIMESTAMP
    # ------------------------------------------------------------

    try:

        timestamp = str(
            create_time
        ).strip()


        if timestamp.endswith(
            "Z"
        ):

            timestamp = (
                timestamp[:-1]
                + "+00:00"
            )


        created = (
            datetime.fromisoformat(
                timestamp
            )
        )


        if created.tzinfo is None:

            created = (
                created.replace(
                    tzinfo=timezone.utc
                )
            )


        return max(
            0.0,
            (
                now
                - created
            ).total_seconds(),
        )


    except (
        TypeError,
        ValueError,
    ):

        return 0.0


# ================================================================
# RSS CONVERSION
# ================================================================

def extract_rss_mb(
    process_data: Mapping[
        str,
        Any,
    ],
) -> float:

    # ------------------------------------------------------------
    # If telemetry already stores MB, use it directly.
    # ------------------------------------------------------------

    rss_mb = first_value(

        process_data,

        "rss_mb",

        "memory_rss_mb",
    )


    if rss_mb is not None:

        return max(
            0.0,
            safe_float(
                rss_mb
            ),
        )


    # ------------------------------------------------------------
    # Otherwise assume RSS value is bytes.
    # ------------------------------------------------------------

    rss_bytes = first_value(

        process_data,

        "rss",

        "rss_bytes",

        "memory_rss",
    )


    if rss_bytes is None:

        return 0.0


    value = safe_float(
        rss_bytes
    )


    return max(
        0.0,
        value
        / (
            1024.0
            * 1024.0
        ),
    )


# ================================================================
# CONTEXT VALUE
#
# Cross-domain counts can come from a behavior tracker later.
# If not supplied, we safely fall back to values in process_data.
# ================================================================

def context_value(

    context: Mapping[
        str,
        Any,
    ],

    process_data: Mapping[
        str,
        Any,
    ],

    key: str,

    *aliases: str,

) -> float:


    if key in context:

        return max(
            0.0,
            safe_float(
                context.get(
                    key
                )
            ),
        )


    value = first_value(

        process_data,

        key,

        *aliases,

        default=0.0,
    )


    return max(
        0.0,
        safe_float(
            value
        ),
    )


# ================================================================
# MAIN PROCESS FEATURE EXTRACTOR
# ================================================================

class ProcessFeatureExtractor:

    def extract(

        self,

        process_data: Mapping[
            str,
            Any,
        ],

        context: Mapping[
            str,
            Any,
        ] | None = None,

    ) -> ProcessFeatureRecord:


        if context is None:

            context = {}


        # --------------------------------------------------------
        # SUPPORT BOTH:
        #
        # process_data = SecurityEvent["process"]
        #
        # and
        #
        # process_data = complete SecurityEvent dictionary
        # --------------------------------------------------------

        nested_process = (
            process_data.get(
                "process"
            )
        )


        if isinstance(
            nested_process,
            Mapping,
        ):

            process_payload = (
                nested_process
            )

        else:

            process_payload = (
                process_data
            )


        # --------------------------------------------------------
        # BASIC PROCESS METADATA
        # --------------------------------------------------------

        pid = safe_int(

            first_value(

                process_payload,

                "pid",

                "process_id",
            )
        )


        process_name = str(

            first_value(

                process_payload,

                "name",

                "process_name",

                default="",
            )

            or ""

        ).strip()


        parent_process_name = str(

            first_value(

                process_payload,

                "parent_name",

                "parent_process_name",

                "parent",

                default="",
            )

            or ""

        ).strip()


        executable_path = str(

            first_value(

                process_payload,

                "exe",

                "executable",

                "executable_path",

                "path",

                default="",
            )

            or ""

        ).strip()


        # --------------------------------------------------------
        # COMMAND LINE
        # --------------------------------------------------------

        raw_command_line = first_value(

            process_payload,

            "cmdline",

            "command_line",

            "command",

            "args",

            default="",
        )


        command_line = (
            normalize_command_line(
                raw_command_line
            )
        )


        command_line_lower = (
            command_line.lower()
        )


        # --------------------------------------------------------
        # NORMALIZE PROCESS NAMES
        # --------------------------------------------------------

        process_name_lower = (

            process_name
            .lower()
        )


        parent_name_lower = (

            parent_process_name
            .lower()
        )


        # --------------------------------------------------------
        # PATH ANALYSIS
        # --------------------------------------------------------

        path_lower = (

            executable_path
            .replace(
                "/",
                "\\",
            )
            .lower()
        )


        is_temp_path = contains_any(

            path_lower,

            TEMP_PATH_MARKERS,
        )


        is_user_profile_path = (
            contains_any(

                path_lower,

                USER_PROFILE_MARKERS,
            )
        )


        is_system_path = contains_any(

            path_lower,

            SYSTEM_PATH_MARKERS,
        )


        # --------------------------------------------------------
        # PROCESS AGE
        # --------------------------------------------------------

        create_time = first_value(

            process_payload,

            "create_time",

            "created_at",

            "start_time",

            "process_start_time",
        )


        process_age_seconds = (
            calculate_process_age_seconds(
                create_time
            )
        )


        # --------------------------------------------------------
        # RESOURCE FEATURES
        # --------------------------------------------------------

        cpu_percent = max(

            0.0,

            safe_float(

                first_value(

                    process_payload,

                    "cpu_percent",

                    "cpu_usage",

                    "cpu",

                    default=0.0,
                )
            ),
        )


        memory_percent = max(

            0.0,

            safe_float(

                first_value(

                    process_payload,

                    "memory_percent",

                    "memory_usage_percent",

                    default=0.0,
                )
            ),
        )


        num_threads = max(

            0.0,

            safe_float(

                first_value(

                    process_payload,

                    "num_threads",

                    "thread_count",

                    "threads",

                    default=0.0,
                )
            ),
        )


        num_handles = max(

            0.0,

            safe_float(

                first_value(

                    process_payload,

                    "num_handles",

                    "handle_count",

                    "handles",

                    default=0.0,
                )
            ),
        )


        # --------------------------------------------------------
        # CROSS-DOMAIN FEATURES
        # --------------------------------------------------------

        child_process_count = (
            context_value(

                context,

                process_payload,

                "child_process_count",

                "children_count",
            )
        )


        network_connection_count = (
            context_value(

                context,

                process_payload,

                "network_connection_count",

                "connection_count",

                "network_count",
            )
        )


        unique_remote_ip_count = (
            context_value(

                context,

                process_payload,

                "unique_remote_ip_count",

                "remote_ip_count",
            )
        )


        file_activity_count = (
            context_value(

                context,

                process_payload,

                "file_activity_count",

                "file_event_count",
            )
        )


        registry_activity_count = (
            context_value(

                context,

                process_payload,

                "registry_activity_count",

                "registry_event_count",
            )
        )


        recent_event_count = (
            context_value(

                context,

                process_payload,

                "recent_event_count",

                "event_count",
            )
        )


        # --------------------------------------------------------
        # COMMAND-LINE FLAGS
        # --------------------------------------------------------

        has_encoded_command = (
            contains_any(

                command_line_lower,

                ENCODED_COMMAND_KEYWORDS,
            )
        )


        has_hidden_flag = (
            contains_any(

                command_line_lower,

                HIDDEN_EXECUTION_KEYWORDS,
            )
        )


        has_download_keyword = (
            contains_any(

                command_line_lower,

                DOWNLOAD_KEYWORDS,
            )
        )


        has_network_tool_keyword = (
            contains_any(

                command_line_lower,

                NETWORK_TOOL_KEYWORDS,
            )
        )


        # --------------------------------------------------------
        # PROCESS TYPE FLAGS
        # --------------------------------------------------------

        is_script_interpreter = (

            process_name_lower
            in SCRIPT_INTERPRETERS
        )


        parent_is_office_app = (

            parent_name_lower
            in OFFICE_APPLICATIONS
        )


        parent_is_script_interpreter = (

            parent_name_lower
            in SCRIPT_INTERPRETERS
        )


        # --------------------------------------------------------
        # BUILD FINAL FEATURES
        # --------------------------------------------------------

        features = (
            ProcessBehaviorFeatures(

                cpu_percent=
                    cpu_percent,

                memory_percent=
                    memory_percent,

                rss_mb=
                    extract_rss_mb(
                        process_payload
                    ),

                num_threads=
                    num_threads,

                num_handles=
                    num_handles,

                process_age_seconds=
                    process_age_seconds,


                child_process_count=
                    child_process_count,

                network_connection_count=
                    network_connection_count,

                unique_remote_ip_count=
                    unique_remote_ip_count,

                file_activity_count=
                    file_activity_count,

                registry_activity_count=
                    registry_activity_count,

                recent_event_count=
                    recent_event_count,


                command_line_length=
                    float(
                        len(
                            command_line
                        )
                    ),

                command_arg_count=
                    float(
                        command_argument_count(
                            raw_command_line
                        )
                    ),


                executable_path_depth=
                    float(
                        calculate_path_depth(
                            executable_path
                        )
                    ),

                is_temp_path=
                    float(
                        is_temp_path
                    ),

                is_user_profile_path=
                    float(
                        is_user_profile_path
                    ),

                is_system_path=
                    float(
                        is_system_path
                    ),


                is_script_interpreter=
                    float(
                        is_script_interpreter
                    ),

                has_encoded_command=
                    float(
                        has_encoded_command
                    ),

                has_hidden_flag=
                    float(
                        has_hidden_flag
                    ),

                has_download_keyword=
                    float(
                        has_download_keyword
                    ),

                has_network_tool_keyword=
                    float(
                        has_network_tool_keyword
                    ),


                parent_is_office_app=
                    float(
                        parent_is_office_app
                    ),

                parent_is_script_interpreter=
                    float(
                        parent_is_script_interpreter
                    ),
            )
        )


        return ProcessFeatureRecord(

            schema_version=
                PROCESS_FEATURE_SCHEMA_VERSION,

            extracted_at=(
                datetime.now(
                    timezone.utc
                ).isoformat()
            ),

            pid=
                pid,

            process_name=(
                process_name
                or None
            ),

            parent_process_name=(
                parent_process_name
                or None
            ),

            executable_path=(
                executable_path
                or None
            ),

            features=
                features,
        )