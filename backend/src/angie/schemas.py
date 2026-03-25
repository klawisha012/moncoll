from pydantic import BaseModel, Field


class ModuleInfo(BaseModel):
    name: str
    loaded: bool


class AngieSettings(BaseModel):
    worker_processes: str = Field(
        default="auto", description="worker_processes: auto or number"
    )
    worker_rlimit_nofile: int = Field(default=65536, description="worker_rlimit_nofile")
    worker_connections: int = Field(
        default=65536, description="worker_connections in events block"
    )
    keepalive_timeout: int = Field(
        default=65, description="keepalive_timeout in seconds"
    )
    sendfile: bool = Field(default=True, description="sendfile on/off")
    denied_countries: list[str] = Field(
        default=["PL", "QA"], description="GeoIP denied country codes"
    )
    modules: list[ModuleInfo] = Field(
        default=[
            ModuleInfo(name="ngx_http_echo_module.so", loaded=True),
            ModuleInfo(name="ngx_http_geoip2_module.so", loaded=True),
            ModuleInfo(name="ngx_stream_geoip2_module.so", loaded=True),
            ModuleInfo(name="ngx_http_modsecurity_module.so", loaded=True),
        ],
        description="Available Angie modules",
    )


class AngieSettingsResponse(AngieSettings):
    pass


class AngieSettingsUpdate(AngieSettings):
    pass
