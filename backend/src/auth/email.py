import logging
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import get_settings

logger = logging.getLogger(__name__)
_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "email_templates"),
    autoescape=select_autoescape(["html"]),
)


async def send_verify_email(*, to_email: str, display_name: str, verify_url: str) -> None:
    body = _env.get_template("verify_email.html").render(
        display_name=display_name, verify_url=verify_url
    )
    await _send(to_email, "Verify your WAF email", body)


async def send_password_reset(*, to_email: str, display_name: str, reset_url: str) -> None:
    body = _env.get_template("reset_password.html").render(
        display_name=display_name, reset_url=reset_url
    )
    await _send(to_email, "Reset your WAF password", body)


async def _send(to_email: str, subject: str, html_body: str) -> None:
    s = get_settings()
    if not s.smtp_host:
        logger.warning("SMTP not configured — would send to %s subj=%s", to_email, subject)
        logger.info("EMAIL BODY (dev):\n%s", html_body)
        return
    msg = EmailMessage()
    msg["From"] = f"{s.smtp_from_name} <{s.smtp_from_email}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content("This message requires an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")
    await aiosmtplib.send(
        msg,
        hostname=s.smtp_host,
        port=s.smtp_port,
        username=s.smtp_username,
        password=s.smtp_password,
        start_tls=s.smtp_starttls,
    )
