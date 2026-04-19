import random
from datetime import datetime, timedelta

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class MetricsResponse(BaseModel):
    total_requests: int
    total_requests_change: float
    blocked_threats: int
    high_severity_count: int
    system_health: float
    avg_latency_ms: int


class TrafficDataPoint(BaseModel):
    timestamp: str
    clean: int
    malicious: int


class ThreatOrigin(BaseModel):
    country: str
    country_code: str
    blocks_percent: float


class SecurityEvent(BaseModel):
    timestamp: str
    type: str
    ip: str
    country: str
    path: str
    severity: str


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics():
    return MetricsResponse(
        total_requests=14293801,
        total_requests_change=12.4,
        blocked_threats=824103,
        high_severity_count=452,
        system_health=99.98,
        avg_latency_ms=12,
    )


@router.get("/traffic", response_model=list[TrafficDataPoint])
async def get_traffic():
    now = datetime.now()
    points = []
    for i in range(15):
        timestamp = now - timedelta(minutes=14 - i)
        clean = random.randint(80000, 120000)
        malicious = random.randint(1000, 5000)
        points.append(
            TrafficDataPoint(
                timestamp=timestamp.strftime("%H:%M:%S"),
                clean=clean,
                malicious=malicious,
            )
        )
    return points


@router.get("/threat-origins", response_model=list[ThreatOrigin])
async def get_threat_origins():
    return [
        ThreatOrigin(country="United States", country_code="US", blocks_percent=42.0),
        ThreatOrigin(country="Russia", country_code="RU", blocks_percent=28.0),
        ThreatOrigin(country="China", country_code="CN", blocks_percent=15.0),
        ThreatOrigin(country="Brazil", country_code="BR", blocks_percent=8.0),
        ThreatOrigin(country="Germany", country_code="DE", blocks_percent=7.0),
    ]


@router.get("/events", response_model=list[SecurityEvent])
async def get_events(limit: int = 50, severity: str = "all"):
    events = [
        SecurityEvent(
            timestamp="2024-05-24 14:12:05",
            type="SQL Injection Attempt",
            ip="192.168.1.105",
            country="RU",
            path="/v1/auth/login",
            severity="Critical",
        ),
        SecurityEvent(
            timestamp="2024-05-24 14:11:42",
            type="Rate Limit Exceeded",
            ip="45.22.112.9",
            country="US",
            path="/api/search",
            severity="Warning",
        ),
        SecurityEvent(
            timestamp="2024-05-24 14:10:15",
            type="TLS Handshake Refused",
            ip="102.13.4.11",
            country="CN",
            path="Global SSL Port 443",
            severity="Info",
        ),
        SecurityEvent(
            timestamp="2024-05-24 14:09:33",
            type="XSS Attempt Blocked",
            ip="185.234.219.45",
            country="UA",
            path="/api/comments",
            severity="Critical",
        ),
        SecurityEvent(
            timestamp="2024-05-24 14:08:22",
            type="Path Traversal",
            ip="91.234.56.78",
            country="NL",
            path="/var/www/html",
            severity="Critical",
        ),
        SecurityEvent(
            timestamp="2024-05-24 14:07:10",
            type="Bot Detection",
            ip="185.212.89.11",
            country="US",
            path="/wp-admin",
            severity="Warning",
        ),
    ]
    return events
