from __future__ import annotations


from fastapi import (
    APIRouter,
    HTTPException,
)


from api.security_runtime_service import (
    SecurityRuntimeService,
)


# ================================================================
# ROUTER
# ================================================================

router = APIRouter(

    prefix="/api/v1/security",

    tags=[
        "Security Runtime"
    ],
)


# ================================================================
# SERVICE
# ================================================================

runtime_service = (
    SecurityRuntimeService()
)


# ================================================================
# SECURITY RUNTIME
#
# GET:
#
#   /api/v1/security/runtime
#
# This endpoint does NOT start SentinelAgent or any collectors.
#
# It only reads:
#
#   collector heartbeat persistence
#   Temporal-v2 metadata
#   Temporal-v2 calibration
#   Fusion-v3 persisted results
#
# ================================================================

@router.get(
    "/runtime"
)
def get_security_runtime():

    try:

        return (
            runtime_service
            .get_runtime_status()
        )


    except Exception as error:

        raise HTTPException(

            status_code=500,

            detail=(
                "Unable to read SENTINEL-X "
                "security runtime status: "
                f"{error}"
            ),
        )