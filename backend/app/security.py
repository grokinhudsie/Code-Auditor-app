import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
from fastapi import Response
from sqlalchemy import delete
from sqlalchemy.orm import Session as DbSession

from app.deps import CORS_ORIGINS, SESSION_COOKIE, hash_token
from shared.models import AuthSession

PRIMARY_ORIGIN = CORS_ORIGINS[0]
COOKIE_SECURE = PRIMARY_ORIGIN.startswith("https")

RP_NAME = "VulnScan Code Auditor"
RP_ID = os.environ.get("WEBAUTHN_RP_ID") or (urlparse(PRIMARY_ORIGIN).hostname or "localhost")

SESSION_TTL = timedelta(days=int(os.environ.get("SESSION_TTL_DAYS") or "30"))

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM") or "VulnScan <onboarding@resend.dev>"


def create_session(db: DbSession, user_id: str) -> str:
    """Mint a session row and return the raw cookie token (only the hash is
    stored). Opportunistically purges expired sessions. Caller commits."""
    now = datetime.now(timezone.utc)
    db.execute(delete(AuthSession).where(AuthSession.expires_at < now))
    token = secrets.token_urlsafe(32)
    db.add(
        AuthSession(
            token_hash=hash_token(token),
            user_id=user_id,
            expires_at=now + SESSION_TTL,
        )
    )
    return token


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def send_email(to: str, subject: str, text: str) -> None:
    if not RESEND_API_KEY:
        # dev mode: no email provider configured
        print(f"[auth] email to {to}: {subject}\n{text}", flush=True)
        return
    resp = httpx.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
        json={"from": RESEND_FROM, "to": [to], "subject": subject, "text": text},
        timeout=10,
    )
    resp.raise_for_status()


def send_email_code(email: str, code: str) -> None:
    if not RESEND_API_KEY:
        # dev mode: keep this exact grep-able line
        print(f"[auth] verification code for {email}: {code}", flush=True)
        return
    send_email(
        email,
        f"{code} is your VulnScan verification code",
        (
            f"Your VulnScan verification code is {code}.\n\n"
            "It expires in 10 minutes. If you didn't request this, ignore this email."
        ),
    )


def send_passkey_added_notice(email: str) -> None:
    send_email(
        email,
        "A new passkey was added to your VulnScan account",
        (
            "A new passkey was just registered on your VulnScan account.\n\n"
            "If this was you, no action is needed. If it wasn't, someone may "
            "have access to your email: sign in, remove the passkey on the "
            "Account page, and secure your mailbox."
        ),
    )
