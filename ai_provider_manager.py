from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests


from ai_config import (
    AI_CONFIG,
    classify_ai_error,
)


# ================================================================
# ENDPOINTS
# ================================================================

GROQ_BASE_URL = (
    "https://api.groq.com/openai/v1"
)


GEMINI_BASE_URL = (
    "https://generativelanguage.googleapis.com/v1beta"
)


# ================================================================
# AI PROVIDER MANAGER
# ================================================================

class AIProviderManager:
    """
    SENTINEL-X centralized AI provider manager.

    Responsibilities:

        - keep provider communication in one place
        - Groq primary provider
        - automatic Groq model failover
        - optional future Gemini fallback
        - classify provider failures
        - never expose API keys
        - never execute endpoint-security actions

    AI threat reasoning remains inside the agents.
    """

    VERSION = "2.0"


    def __init__(
        self,
    ):

        self.config = (
            AI_CONFIG
        )


    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict[str, Any]:

        return {

            "manager":
                "AIProviderManager",

            "version":
                self.VERSION,

            "primary_provider":
                self.config.primary_provider,

            "fallback_provider":
                self.config.fallback_provider,

            "groq": {

                "configured":
                    bool(
                        self.config.groq_api_key
                    ),

                "models":
                    list(
                        self.config.groq_models
                    ),

                "transport":
                    "REST",
            },

            "gemini": {

                "configured":
                    bool(
                        self.config.gemini_api_key
                    ),

                "model":
                    self.config.gemini_model,

                "transport":
                    "REST",
            },

            "simulation_only":
                self.config.simulation_only,

            "timeout_seconds":
                self.config.timeout_seconds,
        }


    # ============================================================
    # ERROR MESSAGE
    # ============================================================

    @staticmethod
    def _extract_error_message(
        response: requests.Response,
    ) -> str:

        try:

            data = response.json()

        except Exception:

            return (
                response.text[:2000]
                or
                f"HTTP {response.status_code}"
            )


        error = data.get(
            "error"
        )


        if isinstance(
            error,
            dict,
        ):

            return str(
                error.get(
                    "message"
                )
                or error
            )


        if error:

            return str(
                error
            )


        return (
            response.text[:2000]
            or
            f"HTTP {response.status_code}"
        )


    # ============================================================
    # GROQ MODEL LIST
    # ============================================================

    def list_groq_models(
        self,
    ) -> Dict[str, Any]:

        if not self.config.groq_api_key:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "error_type":
                    "AUTHENTICATION_FAILURE",

                "error":
                    "GROQ_API_KEY is not configured.",

                "models":
                    [],
            }


        try:

            response = requests.get(

                f"{GROQ_BASE_URL}/models",

                headers={

                    "Authorization":
                        (
                            "Bearer "
                            f"{self.config.groq_api_key}"
                        ),

                    "Content-Type":
                        "application/json",
                },

                timeout=
                    self.config.timeout_seconds,
            )


        except requests.Timeout:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "error_type":
                    "TIMEOUT",

                "error":
                    "Groq model listing timed out.",

                "models":
                    [],
            }


        except Exception as error:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "error_type":
                    classify_ai_error(
                        error
                    ),

                "error":
                    str(
                        error
                    ),

                "models":
                    [],
            }


        if response.status_code != 200:

            message = (
                self._extract_error_message(
                    response
                )
            )


            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "status_code":
                    response.status_code,

                "error_type":
                    classify_ai_error(
                        RuntimeError(
                            f"{response.status_code} {message}"
                        )
                    ),

                "error":
                    message,

                "models":
                    [],
            }


        data = response.json()


        models = sorted(

            str(
                item.get(
                    "id",
                    ""
                )
            )

            for item
            in data.get(
                "data",
                []
            )

            if item.get(
                "id"
            )
        )


        return {

            "success":
                True,

            "provider":
                "GROQ",

            "error_type":
                None,

            "error":
                None,

            "models":
                models,
        }


    # ============================================================
    # SINGLE GROQ MODEL CALL
    # ============================================================

    def _generate_groq_model(
        self,
        *,
        model: str,
        prompt: str,
        system_instruction: Optional[str],
        json_mode: bool,
        temperature: float,
    ) -> Dict[str, Any]:

        messages: List[Dict[str, str]] = []


        if system_instruction:

            messages.append({

                "role":
                    "system",

                "content":
                    system_instruction,
            })


        messages.append({

            "role":
                "user",

            "content":
                prompt,
        })


        payload: Dict[str, Any] = {

            "model":
                model,

            "messages":
                messages,

            "temperature":
                temperature,

            "stream":
                False,
        }


        # --------------------------------------------------------
        # JSON OBJECT MODE
        #
        # The ProtectionDecisionAgent performs its own schema
        # validation after receiving this JSON.
        # --------------------------------------------------------

        if json_mode:

            payload[
                "response_format"
            ] = {

                "type":
                    "json_object"
            }


        try:

            response = requests.post(

                f"{GROQ_BASE_URL}/chat/completions",

                headers={

                    "Authorization":
                        (
                            "Bearer "
                            f"{self.config.groq_api_key}"
                        ),

                    "Content-Type":
                        "application/json",
                },

                json=
                    payload,

                timeout=
                    self.config.timeout_seconds,
            )


        except requests.Timeout:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "model":
                    model,

                "status_code":
                    None,

                "error_type":
                    "TIMEOUT",

                "error":
                    (
                        "Groq generation request "
                        "timed out."
                    ),

                "text":
                    None,
            }


        except Exception as error:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "model":
                    model,

                "status_code":
                    None,

                "error_type":
                    classify_ai_error(
                        error
                    ),

                "error":
                    str(
                        error
                    ),

                "text":
                    None,
            }


        if response.status_code != 200:

            message = (
                self._extract_error_message(
                    response
                )
            )


            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "model":
                    model,

                "status_code":
                    response.status_code,

                "error_type":
                    classify_ai_error(

                        RuntimeError(

                            f"{response.status_code} "
                            f"{message}"
                        )
                    ),

                "error":
                    message,

                "text":
                    None,
            }


        try:

            data = response.json()


            text = (

                data.get(
                    "choices",
                    [{}],
                )[0]

                .get(
                    "message",
                    {}
                )

                .get(
                    "content",
                    ""
                )
            )


            text = str(
                text
                or ""
            ).strip()


        except Exception as error:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "model":
                    model,

                "status_code":
                    response.status_code,

                "error_type":
                    "INVALID_PROVIDER_RESPONSE",

                "error":
                    str(
                        error
                    ),

                "text":
                    None,
            }


        if not text:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "model":
                    model,

                "status_code":
                    response.status_code,

                "error_type":
                    "EMPTY_PROVIDER_RESPONSE",

                "error":
                    "Groq returned no text.",

                "text":
                    None,
            }


        return {

            "success":
                True,

            "provider":
                "GROQ",

            "model":
                model,

            "status_code":
                response.status_code,

            "error_type":
                None,

            "error":
                None,

            "text":
                text,
        }


    # ============================================================
    # GROQ GENERATION + MODEL FAILOVER
    # ============================================================

    def generate_groq(
        self,
        *,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = False,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:

        if not self.config.groq_api_key:

            return {

                "success":
                    False,

                "provider":
                    "GROQ",

                "model":
                    None,

                "error_type":
                    "AUTHENTICATION_FAILURE",

                "error":
                    "GROQ_API_KEY is not configured.",

                "text":
                    None,

                "fallback_used":
                    False,

                "attempts":
                    [],
            }


        attempts = []


        for index, model in enumerate(
            self.config.groq_models
        ):

            result = (
                self._generate_groq_model(

                    model=
                        model,

                    prompt=
                        prompt,

                    system_instruction=
                        system_instruction,

                    json_mode=
                        json_mode,

                    temperature=
                        temperature,
                )
            )


            attempts.append({

                "model":
                    model,

                "success":
                    result.get(
                        "success"
                    ),

                "status_code":
                    result.get(
                        "status_code"
                    ),

                "error_type":
                    result.get(
                        "error_type"
                    ),
            })


            if result.get(
                "success"
            ):

                result[
                    "fallback_used"
                ] = (
                    index > 0
                )

                result[
                    "attempts"
                ] = attempts

                return result


            error_type = (
                result.get(
                    "error_type"
                )
            )


            # ----------------------------------------------------
            # Authentication / permissions / malformed shared
            # request will not improve by switching models.
            # ----------------------------------------------------

            if error_type in {

                "AUTHENTICATION_FAILURE",
                "PERMISSION_FAILURE",
                "BAD_REQUEST",
            }:

                result[
                    "fallback_used"
                ] = False

                result[
                    "attempts"
                ] = attempts

                return result


            # ----------------------------------------------------
            # These may be model-specific, so try next candidate.
            # ----------------------------------------------------

            if error_type in {

                "RATE_LIMIT",
                "TIMEOUT",
                "PROVIDER_UNAVAILABLE",
                "MODEL_OR_ENDPOINT_NOT_FOUND",
            }:

                continue


        return {

            "success":
                False,

            "provider":
                "GROQ",

            "model":
                None,

            "error_type":
                (
                    attempts[-1][
                        "error_type"
                    ]
                    if attempts
                    else
                    "PROVIDER_NOT_AVAILABLE"
                ),

            "error":
                (
                    "All configured Groq models "
                    "failed."
                ),

            "text":
                None,

            "fallback_used":
                len(
                    attempts
                )
                > 1,

            "attempts":
                attempts,
        }


    # ============================================================
    # GEMINI — OPTIONAL FUTURE FALLBACK
    # ============================================================

    def generate_gemini(
        self,
        *,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = False,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:

        if not self.config.gemini_api_key:

            return {

                "success":
                    False,

                "provider":
                    "GEMINI",

                "model":
                    self.config.gemini_model,

                "error_type":
                    "AUTHENTICATION_FAILURE",

                "error":
                    "Gemini API key is not configured.",

                "text":
                    None,
            }


        model = (
            self.config.gemini_model
        )


        url = (

            f"{GEMINI_BASE_URL}/"
            f"models/{model}:generateContent"
        )


        payload: Dict[str, Any] = {

            "contents": [

                {

                    "role":
                        "user",

                    "parts": [

                        {

                            "text":
                                prompt
                        }
                    ],
                }
            ],

            "generationConfig": {

                "temperature":
                    temperature,
            },
        }


        if system_instruction:

            payload[
                "systemInstruction"
            ] = {

                "parts": [

                    {

                        "text":
                            system_instruction
                    }
                ]
            }


        if json_mode:

            payload[
                "generationConfig"
            ][
                "responseMimeType"
            ] = (
                "application/json"
            )


        try:

            response = requests.post(

                url,

                headers={

                    "x-goog-api-key":
                        self.config.gemini_api_key,

                    "Content-Type":
                        "application/json",
                },

                json=
                    payload,

                timeout=
                    self.config.timeout_seconds,
            )


        except requests.Timeout:

            return {

                "success":
                    False,

                "provider":
                    "GEMINI",

                "model":
                    model,

                "error_type":
                    "TIMEOUT",

                "error":
                    "Gemini request timed out.",

                "text":
                    None,
            }


        except Exception as error:

            return {

                "success":
                    False,

                "provider":
                    "GEMINI",

                "model":
                    model,

                "error_type":
                    classify_ai_error(
                        error
                    ),

                "error":
                    str(
                        error
                    ),

                "text":
                    None,
            }


        if response.status_code != 200:

            message = (
                self._extract_error_message(
                    response
                )
            )


            return {

                "success":
                    False,

                "provider":
                    "GEMINI",

                "model":
                    model,

                "status_code":
                    response.status_code,

                "error_type":
                    classify_ai_error(

                        RuntimeError(

                            f"{response.status_code} "
                            f"{message}"
                        )
                    ),

                "error":
                    message,

                "text":
                    None,
            }


        try:

            data = response.json()


            text = (

                data.get(
                    "candidates",
                    [{}],
                )[0]

                .get(
                    "content",
                    {}
                )

                .get(
                    "parts",
                    [{}],
                )[0]

                .get(
                    "text",
                    ""
                )
            )


            text = str(
                text
                or ""
            ).strip()


        except Exception as error:

            return {

                "success":
                    False,

                "provider":
                    "GEMINI",

                "model":
                    model,

                "error_type":
                    "INVALID_PROVIDER_RESPONSE",

                "error":
                    str(
                        error
                    ),

                "text":
                    None,
            }


        return {

            "success":
                True,

            "provider":
                "GEMINI",

            "model":
                model,

            "error_type":
                None,

            "error":
                None,

            "text":
                text,

            "fallback_used":
                False,
        }


    # ============================================================
    # CENTRAL ENTRY POINT
    # ============================================================

    def generate(
        self,
        *,
        prompt: str,
        system_instruction: Optional[str] = None,
        json_mode: bool = False,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:

        provider = (
            self.config.primary_provider
            .strip()
            .upper()
        )


        if provider == "GROQ":

            result = (
                self.generate_groq(

                    prompt=
                        prompt,

                    system_instruction=
                        system_instruction,

                    json_mode=
                        json_mode,

                    temperature=
                        temperature,
                )
            )


        elif provider == "GEMINI":

            result = (
                self.generate_gemini(

                    prompt=
                        prompt,

                    system_instruction=
                        system_instruction,

                    json_mode=
                        json_mode,

                    temperature=
                        temperature,
                )
            )


        else:

            return {

                "success":
                    False,

                "provider":
                    provider,

                "model":
                    None,

                "error_type":
                    "UNKNOWN_PROVIDER",

                "error":
                    (
                        "Unsupported primary provider: "
                        f"{provider}"
                    ),

                "text":
                    None,

                "fallback_used":
                    False,
            }


        # --------------------------------------------------------
        # OPTIONAL PROVIDER-LEVEL FALLBACK
        #
        # Current .env uses NONE, so Gemini will NOT be called.
        # --------------------------------------------------------

        if result.get(
            "success"
        ):

            return result


        fallback_provider = (
            self.config.fallback_provider
            .strip()
            .upper()
        )


        retryable = (
            result.get(
                "error_type"
            )
            in {

                "RATE_LIMIT",
                "TIMEOUT",
                "PROVIDER_UNAVAILABLE",
                "MODEL_OR_ENDPOINT_NOT_FOUND",
            }
        )


        if (
            fallback_provider
            ==
            "GEMINI"

            and

            provider
            !=
            "GEMINI"

            and

            retryable
        ):

            fallback = (
                self.generate_gemini(

                    prompt=
                        prompt,

                    system_instruction=
                        system_instruction,

                    json_mode=
                        json_mode,

                    temperature=
                        temperature,
                )
            )


            fallback[
                "fallback_used"
            ] = True


            fallback[
                "primary_failure"
            ] = {

                "provider":
                    result.get(
                        "provider"
                    ),

                "error_type":
                    result.get(
                        "error_type"
                    ),
            }


            return fallback


        return result


# ================================================================
# SHARED INSTANCE
# ================================================================

shared_ai_provider_manager = (
    AIProviderManager()
)