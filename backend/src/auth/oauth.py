"""OAuth2 client factories for Google and GitHub."""

from fastapi import Request
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


def redirect_uri(provider: str, request: Request | None = None) -> str | None:
    s = get_settings()
    ru = {
        "google": s.oauth_google_redirect_uri,
        "github": s.oauth_github_redirect_uri,
    }.get(provider)
    if not ru or not request:
        return ru

    incoming_host = request.headers.get("host", "")
    if incoming_host and "localhost" not in incoming_host and "127.0.0.1" not in incoming_host:
        # Force https for public domains to ensure compatibility with OAuth providers
        # and prevent schema downgrades behind reverse proxies or Cloudflare.
        scheme = "https"
        path = f"/api/auth/oauth/{provider}/callback"
        return f"{scheme}://{incoming_host}{path}"
    return ru


def scopes_for(provider: str) -> list[str]:
    return GOOGLE_SCOPES if provider == "google" else GITHUB_SCOPES
