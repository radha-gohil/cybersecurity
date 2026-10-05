"""Build a read-only route with the existing incident store and agent pipeline.
No SOC workflow dependency and no persistence calls.
"""
from fastapi import APIRouter, HTTPException
from response.digital_twin_visual_preview import DigitalTwinVisualPreview


def build_digital_twin_visual_router(incident_store, investigation_pipeline):
    router = APIRouter(prefix='/api/v1', tags=['digital-twin-visual-preview'])
    engine = DigitalTwinVisualPreview()

    @router.get('/detected-incidents/{incident_id}/digital-twin-preview')
    def get_visual_preview(incident_id: str):
        incident_id = incident_id.strip()
        if not incident_id:
            raise HTTPException(status_code=400, detail='Incident ID is required.')
        incident = incident_store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail='Detected incident not found.')
        try:
            intelligence = investigation_pipeline.preview_incident(incident)
            return engine.evaluate(incident, intelligence)
        except Exception as error:
            # Avoid leaking internal incident evidence / paths in HTTP errors.
            raise HTTPException(status_code=500, detail='Digital Twin preview failed.') from error

    return router
