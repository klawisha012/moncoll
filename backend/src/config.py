from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WAF_", case_sensitive=False, extra="ignore")

    public_base_url: str = "http://localhost"
    cookie_secure: bool = True
    paseto_key: str | None = None

    turnstile_site_key: str | None = None
    turnstile_secret_key: str | None = None

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str = "noreply@localhost"
    smtp_from_name: str = "WAF"
    smtp_starttls: bool = True

    oauth_google_client_id: str | None = None
    oauth_google_client_secret: str | None = None
    oauth_google_redirect_uri: str | None = None

    oauth_github_client_id: str | None = None
    oauth_github_client_secret: str | None = None
    oauth_github_redirect_uri: str | None = None

    @property
    def oauth_google_enabled(self) -> bool:
        return bool(
            self.oauth_google_client_id
            and self.oauth_google_client_secret
            and self.oauth_google_redirect_uri
        )

    @property
    def oauth_github_enabled(self) -> bool:
        return bool(
            self.oauth_github_client_id
            and self.oauth_github_client_secret
            and self.oauth_github_redirect_uri
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
