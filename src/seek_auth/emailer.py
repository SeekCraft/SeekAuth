"""SeekAuth — email delivery (mailbox verification codes).

By default it uses **console delivery**: the code is only written to the log and
no mail is actually sent. That way local development, self-testing and CI need no
SMTP credentials, and a missing mailbox configuration does not disable the whole
registration flow.

Once ``SEEK_SMTP_HOST`` and friends are configured, it switches to real SMTP
automatically.

Design trade-offs:
* No third-party mail service (SendGrid / Mailgun) — that would mean one more API
  key and one more external dependency, while this project's user center is a
  small self-hosted tool where plain SMTP is enough.
* Delivery failures are not swallowed. The registration flow needs to know
  whether the code actually went out; a silent failure would leave users
  re-requesting a code they can never receive.
"""

from __future__ import annotations

import contextlib
import smtplib
from email.header import Header
from email.mime.text import MIMEText
from typing import Any

from .logging_setup import get_logger

log = get_logger(__name__)


def send_verify_code(to_email: str, code: str, purpose: str) -> None:
    """Send a verification code.

    :param to_email: recipient.
    :param code: the verification code (6 digits).
    :param purpose: ``register`` / ``reset`` / ``bind``, used for the mail copy.

    :raises RuntimeError: SMTP is configured but delivery failed. Console mode
        never raises.
    """
    settings = _settings()
    subject, body = _render(purpose, code)

    if not settings.smtp_host:
        # Console delivery: the code shows up in the log, which is convenient
        # while developing.
        log.info(
            "email (console delivery)",
            to=to_email,
            purpose=purpose,
            code=code,
            hint="configure SMTP to switch to real delivery",
        )
        return

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")  # type: ignore[assignment]
    msg["From"] = settings.smtp_from or settings.smtp_user
    msg["To"] = to_email

    try:
        if settings.smtp_tls:
            server: Any = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
            server.starttls()
    except (OSError, smtplib.SMTPException) as e:
        raise RuntimeError(f"SMTP connection failed: {e}") from e

    try:
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)
        server.sendmail(msg["From"], [to_email], msg.as_string())
    except smtplib.SMTPException as e:
        raise RuntimeError(f"SMTP delivery failed: {e}") from e
    finally:
        # A failing quit() does not change the outcome of this delivery — the
        # mail is already gone. The exception must be suppressed anyway,
        # otherwise a raise inside finally would mask the return value.
        with contextlib.suppress(OSError, smtplib.SMTPException):
            server.quit()

    log.info("email sent", to=to_email, purpose=purpose)


def _render(purpose: str, code: str) -> tuple[str, str]:
    """Build the mail subject and body for the given purpose."""
    titles = {
        "register": "SeekAuth registration code",
        "reset": "SeekAuth password reset code",
        "bind": "SeekAuth NetEase account binding code",
    }
    title = titles.get(purpose, "SeekAuth verification code")
    body = (
        f"Your verification code is: {code}\n"
        f"It is valid for 10 minutes and can be used once.\n"
        f"If you did not request it, please ignore this email.\n"
    )
    return title, body


def _settings() -> Any:
    """Return the process-wide settings. Imported lazily to avoid a cycle with config."""
    from .config import get_settings

    return get_settings()


__all__ = ["send_verify_code"]
