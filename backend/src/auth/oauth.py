"""OAuth2 client factories for Google and GitHub."""

from httpx_oauth.clients.github import GitHubOAuth2
from httpx_oauth.clients.google import GoogleOAuth2

from ..config import get_settings

GOOGLE_SCOPES = ["openid", "email", "profile"]
GITHUB_SCOPES = ["read:user", "user:email"]


def get_client(provider: str) -> GoogleOAuth2 | GitHubOAuth2 | None:
    s = get_settings()
    if provider == "google" and s.oauth_google_enabled:
        return GoogleOAuth2(s.oauth_google_client_id, s.oauth_google_client_secret)
    if provider == "github" and s.oauth_github_enabled:
        return GitHubOAuth2(s.oauth_github_client_id, s.oauth_github_client_secret)
    return None


def redirect_uri(provider: str) -> str | None:
    s = get_settings()
    return {
        "google": s.oauth_google_redirect_uri,
        "github": s.oauth_github_redirect_uri,
    }.get(provider)


def scopes_for(provider: str) -> list[str]:
    return GOOGLE_SCOPES if provider == "google" else GITHUB_SCOPES
