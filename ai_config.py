from __future__ import annotations

import os

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


try:
    from dotenv import load_dotenv

    DOTENV_AVAILABLE = True

except Exception:

    load_dotenv = None

    DOTENV_AVAILABLE = False


# ================================================================
# PROJECT
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parent
)


ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)


# ================================================================
# LOAD .ENV
# ================================================================

if DOTENV_AVAILABLE:

    load_dotenv(
        dotenv_path=ENV_FILE,
        override=False,
    )


# ================================================================
# HELPERS
# ================================================================

def env_string(
    name: str,
    default: Optional[str] = None,
) -> Optional[str]:

    value = os.getenv(
        name
    )

    if value is None:

        return default


    value = value.strip()


    if not value:

        return default


    return value


def env_bool(
    name: str,
    default: bool = False,
) -> bool:

    value = env_string(
        name
    )


    if value is None:

        return default


    return (
        value.lower()
        in {
            "1",
            "true",
            "yes",
            "on",
        }
    )


def env_int(
    name: str,
    default: int,
) -> int:

    value = env_string(
        name
    )


    if value is None:

        return default


    try:

        return int(
            value
        )

    except ValueError:

        return default


def env_list(
    name: str,
    default: Tuple[str, ...],
) -> Tuple[str, ...]:

    value = env_string(
        name
    )


    if not value:

        return default


    values = tuple(

        item.strip()

        for item
        in value.split(",")

        if item.strip()
    )


    return (
        values
        if values
        else default
    )


# ================================================================
# CONFIG
# ================================================================

@dataclass(
    frozen=True
)
class AIRuntimeConfig:

    primary_provider: str

    fallback_provider: str

    timeout_seconds: int

    simulation_only: bool


    # ------------------------------------------------------------
    # GROQ
    # ------------------------------------------------------------

    groq_api_key: Optional[str]

    groq_models: Tuple[str, ...]


    # ------------------------------------------------------------
    # GEMINI
    # ------------------------------------------------------------

    gemini_api_key: Optional[str]

    gemini_model: str


    # ============================================================
    # SAFE STATUS
    # ============================================================

    def status(
        self,
    ) -> dict:

        return {

            "primary_provider":
                self.primary_provider,

            "fallback_provider":
                self.fallback_provider,

            "groq": {

                "configured":
                    bool(
                        self.groq_api_key
                    ),

                "models":
                    list(
                        self.groq_models
                    ),
            },

            "gemini": {

                "configured":
                    bool(
                        self.gemini_api_key
                    ),

                "model":
                    self.gemini_model,
            },

            "timeout_seconds":
                self.timeout_seconds,

            "simulation_only":
                self.simulation_only,

            "env_file":
                str(
                    ENV_FILE
                ),

            "env_file_exists":
                ENV_FILE.exists(),

            "dotenv_available":
                DOTENV_AVAILABLE,
        }


# ================================================================
# LOAD CONFIG
# ================================================================

def load_ai_config() -> AIRuntimeConfig:

    return AIRuntimeConfig(

        primary_provider=(
            env_string(
                "SENTINELX_AI_PRIMARY_PROVIDER",
                "GROQ",
            )
            or "GROQ"
        ).upper(),

        fallback_provider=(
            env_string(
                "SENTINELX_AI_FALLBACK_PROVIDER",
                "NONE",
            )
            or "NONE"
        ).upper(),

        timeout_seconds=
            env_int(
                "SENTINELX_AI_TIMEOUT_SECONDS",
                20,
            ),

        simulation_only=
            env_bool(
                "SENTINELX_AI_SIMULATION_ONLY",
                True,
            ),

        groq_api_key=
            env_string(
                "GROQ_API_KEY"
            ),

        groq_models=
            env_list(

                "SENTINELX_GROQ_MODELS",

                (
                    "openai/gpt-oss-120b",
                    "qwen/qwen3.8-27b",
                    "openai/gpt-oss-20b",
                ),
            ),

        gemini_api_key=(
            env_string(
                "GEMINI_API_KEY"
            )
            or
            env_string(
                "GOOGLE_API_KEY"
            )
        ),

        gemini_model=(
            env_string(
                "SENTINELX_GEMINI_MODEL",
                "gemini-3.1-flash-lite",
            )
            or
            "gemini-3.1-flash-lite"
        ),
    )


# ================================================================
# SHARED CONFIG
# ================================================================

AI_CONFIG = (
    load_ai_config()
)


# ================================================================
# ERROR CLASSIFICATION
# ================================================================

def classify_ai_error(
    error: Exception,
) -> str:

    message = str(
        error
    ).lower()


    if (
        "api_key_invalid" in message
        or
        "api key not valid" in message
        or
        "invalid api key" in message
        or
        "invalid_api_key" in message
        or
        "401" in message
        or
        "unauthorized" in message
    ):

        return "AUTHENTICATION_FAILURE"


    if (
        "403" in message
        or
        "permission_denied" in message
        or
        "permission denied" in message
    ):

        return "PERMISSION_FAILURE"


    if (
        "429" in message
        or
        "rate limit" in message
        or
        "resource_exhausted" in message
        or
        "too_many_requests" in message
        or
        "quota exceeded" in message
    ):

        return "RATE_LIMIT"


    if (
        "404" in message
        or
        "model_not_found" in message
        or
        "not found" in message
    ):

        return "MODEL_OR_ENDPOINT_NOT_FOUND"


    if (
        "timeout" in message
        or
        "timed out" in message
        or
        "deadline_exceeded" in message
    ):

        return "TIMEOUT"


    if (
        "500" in message
        or
        "502" in message
        or
        "503" in message
        or
        "504" in message
        or
        "unavailable" in message
    ):

        return "PROVIDER_UNAVAILABLE"


    if (
        "400" in message
        or
        "bad request" in message
        or
        "invalid_argument" in message
    ):

        return "BAD_REQUEST"


    return "UNKNOWN_AI_ERROR"