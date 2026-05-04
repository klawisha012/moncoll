from typing import List
import docker
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


class ContainerMetrics(BaseModel):
    name: str
    cpu: float
    memory: float
    memory_percent: float
    network_rx: float
    network_tx: float


class MetricsResponse(BaseModel):
    containers: List[ContainerMetrics]


def get_docker_client():
    return docker.from_env()


@router.get("/metrics", response_model=MetricsResponse)
def get_container_metrics():
    try:
        client = get_docker_client()
        containers = client.containers.list()
        metrics = []

        for container in containers:
            stats = container.stats(stream=False)
            
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
            cpu_percent = (cpu_delta / system_delta) * 100.0 if system_delta > 0 else 0.0
            
            memory_usage = stats["memory_stats"]["usage"]
            memory_limit = stats["memory_stats"]["limit"]
            memory_percent = (memory_usage / memory_limit) * 100.0 if memory_limit > 0 else 0.0
            
            networks = stats.get("networks", {})
            network_rx = sum(n.get("rx_bytes", 0) for n in networks.values())
            network_tx = sum(n.get("tx_bytes", 0) for n in networks.values())

            metrics.append(ContainerMetrics(
                name=container.name,
                cpu=cpu_percent,
                memory=memory_usage / (1024 * 1024),
                memory_percent=memory_percent,
                network_rx=network_rx,
                network_tx=network_tx,
            ))

        return MetricsResponse(containers=metrics)
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