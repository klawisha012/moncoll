from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.session import get_session
from . import service as connection_service
from .schemas import Connection, ConnectionCreate, ConnectionUpdate

connections_router = APIRouter(prefix="/api/connections", tags=["connections"])


@connections_router.get("/", response_model=list[Connection])
async def list_connections(session: AsyncSession = Depends(get_session)):
    """List all site connections."""
    return await connection_service.list_connections(session)


@connections_router.get("/{connection_id}", response_model=Connection)
async def get_connection(connection_id: int, session: AsyncSession = Depends(get_session)):
    """Get a specific connection by ID."""
    conn = await connection_service.get_connection(session, connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.post("/", response_model=Connection, status_code=201)
async def create_connection(
    connection: ConnectionCreate,
    session: AsyncSession = Depends(get_session),
):
    """Create a new site connection."""
    return await connection_service.create_connection(session, connection)


@connections_router.put("/{connection_id}", response_model=Connection)
async def update_connection(
    connection_id: int,
    connection: ConnectionUpdate,
    session: AsyncSession = Depends(get_session),
):
    """Update an existing connection."""
    conn = await connection_service.update_connection(session, connection_id, connection)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


@connections_router.delete("/{connection_id}", status_code=204)
async def delete_connection(
    connection_id: int,
    session: AsyncSession = Depends(get_session),
):
    """Delete a connection."""
    success = await connection_service.delete_connection(session, connection_id)
    if not success:
        raise HTTPException(status_code=404, detail="Connection not found")
    return None


@connections_router.post("/upload-static")
async def upload_static_file(
    file: UploadFile = File(...),
):
    """Upload a static site file (e.g. index.html) via the browser file picker.

    Returns a backend-accessible path that can be used as ``static_dir``
    when creating or updating a connection.
    """
    content = await file.read()
    result = connection_service.save_uploaded_static(
        content,
        file.filename or "index.html",
    )
    return result


@connections_router.post("/reload")
async def reload_connections(session: AsyncSession = Depends(get_session)):
    """Regenerate Nginx config files for all connections."""
    result = await connection_service.reload_connections_config(session)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])
    return {"success": True, "message": result["message"]}
