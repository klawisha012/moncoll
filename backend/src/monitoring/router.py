import asyncio
from typing import List, Optional
import docker
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])

# Docker sets this absurdly high value when no memory limit is configured
_DOCKER_UNLIMITED_MEMORY = 9223372036854771712  # INT64_MAX ~ 8 EB


class ContainerMetrics(BaseModel):
    name: str
    cpu: float
    memory: float
    memory_percent: float
    network_rx: float
    network_tx: float


class MetricsResponse(BaseModel):
    containers: List[ContainerMetrics]


def get_docker_client() -> docker.DockerClient:
    return docker.from_env()


def _get_compose_project(client: docker.DockerClient) -> Optional[str]:
    """Detect the docker-compose project name from the backend's own container."""
    try:
        own_id = None

        # 1) Hostname = short container ID (works everywhere: Linux, Docker Desktop, WSL)
        import socket
        candidate = socket.gethostname()
        if candidate and len(candidate) >= 12:
            own_id = candidate

        # 2) Fallback: read /proc/self/cgroup (Linux cgroup v1/v2)
        if not own_id:
            for path in ("/proc/self/cgroup", "/proc/1/cgroup"):
                try:
                    with open(path) as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 3:
                                segment = parts[-1]
                                if "docker-" in segment:
                                    own_id = segment.rsplit("docker-", 1)[-1].rstrip(".scope").split("/")[0]
                                    break
                            elif "docker/" in line:
                                own_id = line.strip().split("docker/", 1)[-1].split("/")[0]
                                break
                except FileNotFoundError:
                    continue
                if own_id:
                    break

        # 3) Last resort: iterate all containers and find ours by matching hostname
        if not own_id:
            import socket as _socket
            hostname = _socket.gethostname()
            for c in client.containers.list():
                if c.id.startswith(hostname) or c.name == hostname:
                    own_id = c.id
                    break

        if own_id:
            try:
                own_container = client.containers.get(own_id)
                return own_container.labels.get("com.docker.compose.project")
            except Exception:
                pass
    except Exception:
        pass
    return None


def _calculate_container_stats(container) -> ContainerMetrics:
    """Extract metrics from a single container (runs in thread pool)."""
    stats = container.stats(stream=False)

    # --- CPU ---
    cpu_stats = stats["cpu_stats"]
    precpu_stats = stats["precpu_stats"]
    cpu_delta = cpu_stats["cpu_usage"]["total_usage"] - precpu_stats["cpu_usage"]["total_usage"]
    system_delta = cpu_stats.get("system_cpu_usage", 0) - precpu_stats.get("system_cpu_usage", 0)
    num_cpus = cpu_stats.get("online_cpus", 1)

    if system_delta > 0 and num_cpus > 0:
        cpu_percent = (cpu_delta / system_delta) * num_cpus * 100.0
    else:
        cpu_percent = 0.0

    # --- Memory ---
    mem_stats = stats["memory_stats"]
    memory_usage = mem_stats["usage"]
    memory_limit = mem_stats["limit"]

    # If limit is the "unlimited" sentinel, fall back to the host total reported by Docker
    if memory_limit >= _DOCKER_UNLIMITED_MEMORY or memory_limit <= 0:
        # Use the hierarchical memory limit from cgroup (often == host RAM)
        memory_limit = mem_stats.get("hierarchical_memory_limit", 0)
    if memory_limit >= _DOCKER_UNLIMITED_MEMORY or memory_limit <= 0:
        # Last resort: total_rss + total_cache from stats
        stats_mem = mem_stats.get("stats", {})
        memory_limit = stats_mem.get("total_rss", 0) + stats_mem.get("total_cache", 0)
        if memory_limit <= 0:
            memory_limit = 1  # avoid division by zero

    memory_mb = memory_usage / (1024 * 1024)
    memory_percent = (memory_usage / memory_limit) * 100.0

    # --- Network ---
    networks = stats.get("networks", {})
    network_rx = sum(n.get("rx_bytes", 0) for n in networks.values())
    network_tx = sum(n.get("tx_bytes", 0) for n in networks.values())

    return ContainerMetrics(
        name=container.name,
        cpu=round(cpu_percent, 2),
        memory=round(memory_mb, 2),
        memory_percent=round(memory_percent, 2),
        network_rx=network_rx,
        network_tx=network_tx,
    )


@router.get("/metrics", response_model=MetricsResponse)
async def get_container_metrics():
    try:
        client = get_docker_client()
        compose_project = _get_compose_project(client)

        all_containers = client.containers.list()

        # Filter to only the current compose project (if detectable)
        if compose_project:
            containers = [
                c for c in all_containers
                if c.labels.get("com.docker.compose.project") == compose_project
            ]
        else:
            # Fallback: exclude obvious system containers
            containers = [
                c for c in all_containers
                if not c.name.startswith("/")
            ]

        # Fetch stats for all containers concurrently via thread pool
        loop = asyncio.get_running_loop()
        metrics = await asyncio.gather(*[
            loop.run_in_executor(None, _calculate_container_stats, c)
            for c in containers
        ])

        return MetricsResponse(containers=list(metrics))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/containers")
def list_containers():
    try:
        client = get_docker_client()
        containers = client.containers.list()
        return {
            "containers": [
                {
                    "id": c.id,
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else c.image.id,
                }
                for c in containers
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))