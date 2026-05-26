"""ModSecurity management router.

Scope decision: ModSecurity rules are global filesystem configs (loaded once
at http scope by Angie). There are no per-tenant rule directories yet — that
is deferred to Phase 13. The frontend exposes the config editor to clients
(role="client"), so the backend uses `require_verified`. Per-connection
ModSec state lives on /api/connections/{id}/security and is tenant-scoped.
"""

import logging

import docker
from fastapi import APIRouter, Depends, HTTPException, status

from ..auth.dependencies import require_verified
from ..db.models import User
from . import service as modsecurity_service
from .exceptions import ConfigNotFoundError, InvalidRuleError
from .schemas import (
    ModSecurityConfigResponse,
    ModSecurityConfigUpdate,
    ReloadResponse,
    RuleCreate,
    RuleItem,
    RuleResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/modsecurity", tags=["modsecurity"])

CONTAINER_NAME = "waf-angie-1"


def get_angie_container():
    client = docker.from_env()
    return client.containers.get(CONTAINER_NAME)


@router.get("/config", response_model=ModSecurityConfigResponse)
async def get_config(_: User = Depends(require_verified)):
    try:
        content, file_path = modsecurity_service.config_service.get_config()
        return ModSecurityConfigResponse(content=content, file_path=str(file_path))
    except ConfigNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.get("/rules", response_model=ModSecurityConfigResponse)
async def get_rules(_: User = Depends(require_verified)):
    try:
        content, file_path = modsecurity_service.config_service.get_rules()
        return ModSecurityConfigResponse(content=content, file_path=str(file_path))
    except ConfigNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e


@router.get("/rules/list", response_model=list[RuleItem])
async def list_rules(_: User = Depends(require_verified)):
    return modsecurity_service.config_service.list_rules()


@router.put("/config", response_model=ModSecurityConfigResponse)
async def update_config(update: ModSecurityConfigUpdate, _: User = Depends(require_verified)):
    file_path = modsecurity_service.config_service.update_config(update.content)
    return ModSecurityConfigResponse(content=update.content, file_path=str(file_path))


@router.put("/rules", response_model=ModSecurityConfigResponse)
async def update_rules(update: ModSecurityConfigUpdate, _: User = Depends(require_verified)):
    file_path = modsecurity_service.config_service.update_rules(update.content)
    return ModSecurityConfigResponse(content=update.content, file_path=str(file_path))


@router.post("/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
async def add_rule(rule: RuleCreate, _: User = Depends(require_verified)):
    try:
        rule_id, _ = modsecurity_service.config_service.add_rule(rule.rule)
        return RuleResponse(
            rule=rule.rule, id=rule_id, success=True, message="Rule added successfully"
        )
    except InvalidRuleError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(rule_id: int, _: User = Depends(require_verified)):
    success = modsecurity_service.config_service.delete_rule(rule_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with id {rule_id} not found",
        )


@router.post("/reload", response_model=ReloadResponse)
async def reload_angie(_: User = Depends(require_verified)):
    try:
        container = get_angie_container()

        exit_code, output = container.exec_run(["angie", "-t"])
        if exit_code != 0:
            return ReloadResponse(
                success=False,
                message=f"Config test failed: {output.decode()}",
            )

        exit_code, output = container.exec_run(["angie", "-s", "reload"])
        if exit_code != 0:
            return ReloadResponse(
                success=False,
                message=f"Reload failed: {output.decode()}",
            )

        return ReloadResponse(success=True, message="Angie reloaded successfully")
    except docker.errors.NotFound:
        return ReloadResponse(success=False, message=f"Container '{CONTAINER_NAME}' not found")
    except Exception as e:
        logger.exception("Failed to reload Angie (ModSecurity router)")
        return ReloadResponse(success=False, message=str(e))


