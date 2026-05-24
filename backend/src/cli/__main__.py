import typer

from .create_admin import create_admin_cmd

app = typer.Typer(help="WAF admin CLI")
app.command("create-admin")(create_admin_cmd)

if __name__ == "__main__":
    app()
