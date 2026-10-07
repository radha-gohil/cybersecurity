"""
SENTINEL-X Digital Twin Visual Preview Router

Read-only preview route.

IMPORTANT:
- Does not create SOC cases.
- Does not create approvals.
- Does not persist response actions.
- Does not execute endpoint actions.
- Uses the same hydrated incident contract as AI Investigation.
"""

from fastapi import (
    APIRouter,
    HTTPException,
)

from response.digital_twin_visual_preview import (
    DigitalTwinVisualPreview,
)


def build_digital_twin_visual_router(
    incident_store,
    investigation_pipeline,
    incident_hydrator=None,
):
    """
    Build the read-only Digital Twin preview router.

    Parameters
    ----------
    incident_store:
        Existing detected-incident store.

    investigation_pipeline:
        Existing MultiAgentSecurityPipeline instance.

    incident_hydrator:
        Optional callable used to convert the lightweight
        stored correlation incident into the canonical
        analysis contract.

        This is important because AI Investigation and
        Digital Twin must receive the SAME:

        - persisted timeline
        - persisted detections
        - process/file/network/registry evidence
        - validation context
        - synthetic-validation context

    No data is persisted by this router.
    """

    router = APIRouter(
        prefix="/api/v1",
        tags=[
            "digital-twin-visual-preview",
        ],
    )

    engine = (
        DigitalTwinVisualPreview()
    )

    # ============================================================
    # READ-ONLY DIGITAL TWIN PREVIEW
    # ============================================================

    @router.get(
        "/detected-incidents/"
        "{incident_id}/digital-twin-preview"
    )
    def get_visual_preview(
        incident_id: str,
    ):
        """
        Build a read-only Digital Twin protection preview.

        This endpoint:

        1. Retrieves the stored detected incident.
        2. Hydrates it using the same contract used by
           AI Investigation.
        3. Runs the read-only multi-agent preview.
        4. Builds the evidence-aware Digital Twin.
        5. Compares hypothetical response plans.

        It never executes a real protection action.
        """

        incident_id = (
            incident_id.strip()
        )

        if not incident_id:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Incident ID is required."
                ),
            )

        # --------------------------------------------------------
        # LOAD STORED INCIDENT
        # --------------------------------------------------------

        try:

            incident = (
                incident_store.get_incident(
                    incident_id
                )
            )

        except Exception as error:

            raise HTTPException(
                status_code=500,
                detail=(
                    "Unable to retrieve the "
                    "detected incident."
                ),
            ) from error

        if incident is None:

            raise HTTPException(
                status_code=404,
                detail=(
                    "Detected incident "
                    "not found."
                ),
            )

        try:

            # ====================================================
            # CANONICAL INCIDENT HYDRATION
            #
            # This is the critical part.
            #
            # AI Investigation already receives the hydrated
            # contract. Digital Twin must receive the exact
            # same contract so validation semantics do not
            # diverge between pages.
            # ====================================================

            if callable(
                incident_hydrator
            ):

                incident = (
                    incident_hydrator(
                        incident
                    )
                )

            if not isinstance(
                incident,
                dict,
            ):

                raise ValueError(
                    "Incident hydrator returned "
                    "an invalid incident."
                )

            # ----------------------------------------------------
            # IDENTITY SAFETY
            # ----------------------------------------------------

            hydrated_id = str(
                incident.get(
                    "incident_id"
                )
                or ""
            )

            if (
                hydrated_id
                and
                hydrated_id
                !=
                incident_id
            ):

                raise ValueError(
                    "Hydrated incident identity "
                    "does not match requested "
                    "incident."
                )

            # ====================================================
            # READ-ONLY INVESTIGATION
            # ====================================================

            intelligence = (
                investigation_pipeline
                .preview_incident(
                    incident
                )
            )

            if not isinstance(
                intelligence,
                dict,
            ):

                raise ValueError(
                    "Investigation pipeline "
                    "returned invalid data."
                )

            # ====================================================
            # DIGITAL TWIN PREVIEW
            # ====================================================

            result = (
                engine.evaluate(
                    incident,
                    intelligence,
                )
            )

            if not isinstance(
                result,
                dict,
            ):

                raise ValueError(
                    "Digital Twin preview "
                    "returned invalid data."
                )

            # ----------------------------------------------------
            # ENFORCE READ-ONLY CONTRACT
            # ----------------------------------------------------

            result[
                "preview_only"
            ] = True

            result[
                "simulation_mode"
            ] = True

            result[
                "real_endpoint_modified"
            ] = False

            result[
                "response_authorized"
            ] = False

            result[
                "approval_eligible"
            ] = False

            result[
                "soc_case_created"
            ] = False

            return result

        except HTTPException:

            raise

        except Exception as error:

            # Do not expose internal telemetry,
            # filesystem paths or private evidence
            # through the HTTP error response.

            raise HTTPException(
                status_code=500,
                detail=(
                    "Digital Twin preview failed."
                ),
            ) from error

    return router