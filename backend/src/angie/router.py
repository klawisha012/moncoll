from fastapi import APIRouter, HTTPException, status
import docker

from .schemas import AngieSettings, AngieSettingsResponse, AngieSettingsUpdate
from . import service as angie_service


router = APIRouter(prefix="/angie", tags=["angie"])

CONTAINER_NAME = "waf-angie-1"


def get_angie_container():
    client = docker.from_env()
    return client.containers.get(CONTAINER_NAME)


@router.get("/settings", response_model=AngieSettingsResponse)
async def get_settings():
    return angie_service.get_angie_settings()


@router.put("/settings", response_model=AngieSettingsResponse)
async def update_settings(update: AngieSettingsUpdate):
    angie_service.save_angie_settings(update)
    return update


@router.post("/reload")
async def reload_angie():
    try:
        container = get_angie_container()

        exit_code, output = container.exec_run(["angie", "-t"])
        if exit_code != 0:
            return {
                "success": False,
                "message": f"Config test failed: {output.decode()}",
            }

        exit_code, output = container.exec_run(["angie", "-s", "reload"])
        if exit_code != 0:
            return {"success": False, "message": f"Reload failed: {output.decode()}"}

        return {"success": True, "message": "Angie reloaded successfully"}
    except docker.errors.NotFound:
        return {"success": False, "message": f"Container '{CONTAINER_NAME}' not found"}
    except Exception as e:
        return {"success": False, "message": str(e)}
