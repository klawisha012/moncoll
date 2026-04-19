from fastapi import APIRouter, HTTPException
from typing import List

from . import service as connection_service
from .schemas import Connection, ConnectionCreate, ConnectionUpdate

connections_router = APIRouter(prefix="/api/connections", tags=["connections"])


@connections_router.get("/", response_model=List[Connection])
async def list_connections():
    """List all site connections."""
    return connection_service.list_connections()


@connections_router.get("/{connection_id}", response_model=Connection)
async def get_connection(connection_id: int):
    """Get a specific connection by ID."""
    conn = connection_service.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.post("/", response_model=Connection, status_code=201)
async def create_connection(connection: ConnectionCreate):
    """Create a new site connection."""
    return connection_service.create_connection(connection)


@connections_router.put("/{connection_id}", response_model=Connection)
async def update_connection(connection_id: int, connection: ConnectionUpdate):
    """Update an existing connection."""
    conn = connection_service.update_connection(connection_id, connection)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.delete("/{connection_id}", status_code=204)
async def delete_connection(connection_id: int):
    """Delete a connection."""
    success = connection_service.delete_connection(connection_id)
    if not success:
        raise HTTPException(status_code=404, detail="Connection not found")
    return None


@connections_router.post("/reload")
async def reload_connections():
    """Regenerate Nginx config files for all connections."""
    result = connection_service.reload_connections_config()
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    return {"success": True, "message": result["message"]}
