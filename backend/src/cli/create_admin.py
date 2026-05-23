import asyncio
import getpass
import secrets

import typer

from ..auth import service as auth
from ..db.base import get_sessionmaker


def create_admin_cmd(
    email: str = typer.Option(..., "--email", help="Admin email address"),
    password: str | None = typer.Option(None, "--password", help="Password (prompted if omitted)"),
) -> None:
    """Create a platform admin user. Prompts for password if --password not given."""

    async def _run() -> None:
        Session = get_sessionmaker()
        async with Session() as session:
            pw = (
                password
                or getpass.getpass("Admin password (blank = auto-generate): ")
                or secrets.token_urlsafe(16)
            )
            try:
                user = await auth.create_admin(session, email=email, password=pw)
            except auth.EmailTaken:
                typer.echo(f"Error: email {email!r} is already in use.", err=True)
                raise typer.Exit(1) from None

            typer.echo(f"Created admin id={user.id} email={user.email}")
            if not password:
                typer.echo(f"PASSWORD: {pw}")

    asyncio.run(_run())
