import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
)

from app import security
from app.deps import (
    CORS_ORIGINS,
    SESSION_COOKIE,
    check_origin,
    client_ip,
    get_current_user,
    hash_token,
    rate_limit,
    redis_client,
    require_auth,
)
from shared.db import SessionLocal
from shared.models import AuthSession, User, WebAuthnCredential

router = APIRouter(prefix="/auth", dependencies=[Depends(require_auth)])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

CODE_TTL = 600  # email verification codes
CHALLENGE_TTL = 300  # webauthn challenges
REG_TOKEN_TTL = 900  # email-verified, awaiting passkey registration
MAX_CODE_ATTEMPTS = 5

OAUTH_STATE_COOKIE = "gh_oauth_state"


def _normalize_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email) or len(email) > 254:
        raise HTTPException(422, "invalid email address")
    return email


def _safe_next(path: str | None) -> str:
    # relative path only: kills open redirects and protocol-relative //host
    if path and path.startswith("/") and not path.startswith("//"):
        return path
    return "/"


class EmailCodeRequest(BaseModel):
    email: str


class EmailVerifyRequest(BaseModel):
    email: str
    code: str


class RegisterOptionsRequest(BaseModel):
    registration_token: str


class RegisterVerifyRequest(BaseModel):
    registration_token: str
    credential: dict


class LoginOptionsRequest(BaseModel):
    email: str


class LoginVerifyRequest(BaseModel):
    email: str
    credential: dict


@router.post("/email/code", status_code=202)
def email_code(req: EmailCodeRequest, request: Request) -> dict:
    check_origin(request)
    email = _normalize_email(req.email)
    rate_limit("authcode-email", email, 3, 900)
    rate_limit("authcode-ip", client_ip(request), 10, 3600)

    code = f"{secrets.randbelow(1_000_000):06d}"
    redis_client.setex(
        f"authcode:{email}", CODE_TTL, hashlib.sha256(code.encode()).hexdigest()
    )
    redis_client.delete(f"authcode-attempts:{email}")
    security.send_email_code(email, code)
    # always 202: don't reveal whether the email has an account
    return {"status": "sent"}


@router.post("/email/verify")
def email_verify(req: EmailVerifyRequest, request: Request) -> dict:
    check_origin(request)
    email = _normalize_email(req.email)
    key = f"authcode:{email}"
    stored = redis_client.get(key)
    if stored is None:
        raise HTTPException(400, "invalid or expired code")

    attempts_key = f"authcode-attempts:{email}"
    attempts = redis_client.incr(attempts_key)
    redis_client.expire(attempts_key, CODE_TTL)
    if attempts > MAX_CODE_ATTEMPTS:
        redis_client.delete(key)
        raise HTTPException(400, "invalid or expired code")

    supplied = hashlib.sha256(req.code.strip().encode()).hexdigest()
    if not hmac.compare_digest(stored.decode(), supplied):
        raise HTTPException(400, "invalid or expired code")

    redis_client.delete(key, attempts_key)
    reg_token = secrets.token_urlsafe(32)
    redis_client.setex(f"regtok:{reg_token}", REG_TOKEN_TTL, email)
    return {"registration_token": reg_token}


def _email_for_reg_token(token: str) -> str:
    email = redis_client.get(f"regtok:{token}")
    if email is None:
        raise HTTPException(400, "registration expired, verify your email again")
    return email.decode()


@router.post("/webauthn/register/options")
def webauthn_register_options(req: RegisterOptionsRequest, request: Request) -> Response:
    check_origin(request)
    email = _email_for_reg_token(req.registration_token)

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).one_or_none()
        existing = (
            db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user.id).all()
            if user
            else []
        )

    options = generate_registration_options(
        rp_id=security.RP_ID,
        rp_name=security.RP_NAME,
        user_name=email,
        # stable, non-PII user handle so re-registration overwrites instead of duplicating
        user_id=hashlib.sha256(email.encode()).digest(),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.id)) for c in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED
        ),
    )
    redis_client.setex(
        f"wanchal:reg:{req.registration_token}", CHALLENGE_TTL, options.challenge
    )
    return Response(options_to_json(options), media_type="application/json")


@router.post("/webauthn/register/verify")
def webauthn_register_verify(req: RegisterVerifyRequest, request: Request) -> Response:
    check_origin(request)
    email = _email_for_reg_token(req.registration_token)

    chal_key = f"wanchal:reg:{req.registration_token}"
    challenge = redis_client.get(chal_key)
    redis_client.delete(chal_key)  # single-use
    if challenge is None:
        raise HTTPException(400, "challenge expired, try again")

    try:
        verification = verify_registration_response(
            credential=json.dumps(req.credential),
            expected_challenge=challenge,
            expected_rp_id=security.RP_ID,
            expected_origin=CORS_ORIGINS,
        )
    except Exception:
        raise HTTPException(400, "passkey registration failed")

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).one_or_none()
        if user is None:
            user = User(email=email, email_verified=True)
            db.add(user)
            db.flush()
        else:
            # verified-email link rule: proving the mailbox attaches the passkey
            user.email_verified = True
        db.merge(
            WebAuthnCredential(
                id=bytes_to_base64url(verification.credential_id),
                user_id=user.id,
                public_key=bytes_to_base64url(verification.credential_public_key),
                sign_count=verification.sign_count,
                transports=req.credential.get("response", {}).get("transports"),
            )
        )
        token = security.create_session(db, user.id)
        payload = user.to_dict()
        db.commit()

    redis_client.delete(f"regtok:{req.registration_token}")
    response = JSONResponse({"user": payload})
    security.set_session_cookie(response, token)
    return response


@router.post("/webauthn/login/options")
def webauthn_login_options(req: LoginOptionsRequest, request: Request) -> Response:
    check_origin(request)
    rate_limit("walogin-ip", client_ip(request), 30, 900)
    email = _normalize_email(req.email)

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).one_or_none()
        creds = (
            db.query(WebAuthnCredential).filter(WebAuthnCredential.user_id == user.id).all()
            if user
            else []
        )

    # unknown email → options with empty allowCredentials (no user enumeration)
    options = generate_authentication_options(
        rp_id=security.RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.id)) for c in creds
        ],
    )
    redis_client.setex(f"wanchal:login:{email}", CHALLENGE_TTL, options.challenge)
    return Response(options_to_json(options), media_type="application/json")


@router.post("/webauthn/login/verify")
def webauthn_login_verify(req: LoginVerifyRequest, request: Request) -> Response:
    check_origin(request)
    rate_limit("walogin-ip", client_ip(request), 30, 900)
    email = _normalize_email(req.email)

    chal_key = f"wanchal:login:{email}"
    challenge = redis_client.get(chal_key)
    redis_client.delete(chal_key)  # single-use
    if challenge is None:
        raise HTTPException(400, "challenge expired, try again")

    credential_id = req.credential.get("id", "")

    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).one_or_none()
        cred = db.get(WebAuthnCredential, credential_id) if credential_id else None
        if user is None or cred is None or cred.user_id != user.id:
            raise HTTPException(400, "passkey sign-in failed")

        try:
            verification = verify_authentication_response(
                credential=json.dumps(req.credential),
                expected_challenge=challenge,
                expected_rp_id=security.RP_ID,
                expected_origin=CORS_ORIGINS,
                credential_public_key=base64url_to_bytes(cred.public_key),
                credential_current_sign_count=cred.sign_count,
            )
        except Exception:
            raise HTTPException(400, "passkey sign-in failed")

        cred.sign_count = verification.new_sign_count
        cred.last_used_at = datetime.now(timezone.utc)
        token = security.create_session(db, user.id)
        payload = user.to_dict()
        db.commit()

    response = JSONResponse({"user": payload})
    security.set_session_cookie(response, token)
    return response


@router.get("/github/start")
def github_start(request: Request, next: str | None = None) -> Response:
    if not security.GITHUB_CLIENT_ID:
        raise HTTPException(503, "GitHub login is not configured")
    state = secrets.token_urlsafe(24)
    params = urlencode(
        {
            "client_id": security.GITHUB_CLIENT_ID,
            "redirect_uri": f"{security.PRIMARY_ORIGIN}/api/auth/github/callback",
            "scope": "read:user user:email",
            "state": state,
        }
    )
    response = RedirectResponse(
        f"https://github.com/login/oauth/authorize?{params}", status_code=302
    )
    response.set_cookie(
        OAUTH_STATE_COOKIE,
        f"{state}:{_safe_next(next)}",
        max_age=600,
        httponly=True,
        samesite="lax",
        secure=security.COOKIE_SECURE,
        path="/api/auth",
    )
    return response


def _oauth_fail(error: str) -> Response:
    response = RedirectResponse(f"/login?error={error}", status_code=302)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
    return response


@router.get("/github/callback")
def github_callback(request: Request, code: str = "", state: str = "") -> Response:
    cookie_state, _, next_path = request.cookies.get(OAUTH_STATE_COOKIE, "").partition(":")
    if not code or not cookie_state or not hmac.compare_digest(state, cookie_state):
        return _oauth_fail("oauth_state")

    try:
        token_resp = httpx.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": security.GITHUB_CLIENT_ID,
                "client_secret": security.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{security.PRIMARY_ORIGIN}/api/auth/github/callback",
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        access_token = token_resp.json().get("access_token")
        if not access_token:
            return _oauth_fail("github_token")

        gh = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        profile = httpx.get("https://api.github.com/user", headers=gh, timeout=10).json()
        emails = httpx.get(
            "https://api.github.com/user/emails", headers=gh, timeout=10
        ).json()
    except httpx.HTTPError:
        return _oauth_fail("github_unreachable")

    email = next(
        (
            e["email"]
            for e in emails
            if isinstance(e, dict) and e.get("primary") and e.get("verified")
        ),
        None,
    )
    if not email:
        return _oauth_fail("github_email_unverified")
    email = email.strip().lower()
    github_id = profile.get("id")

    with SessionLocal() as db:
        user = db.query(User).filter(User.github_id == github_id).one_or_none()
        if user is None:
            # verified-email link rule: same mailbox = same account
            user = db.query(User).filter(User.email == email).one_or_none()
        if user is None:
            user = User(email=email, email_verified=True)
            db.add(user)
            db.flush()
        user.github_id = github_id
        user.email_verified = True
        user.display_name = user.display_name or profile.get("name") or profile.get("login")
        user.avatar_url = profile.get("avatar_url") or user.avatar_url
        token = security.create_session(db, user.id)
        db.commit()

    response = RedirectResponse(_safe_next(next_path), status_code=302)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth")
    security.set_session_cookie(response, token)
    return response


@router.post("/logout", status_code=204)
def logout(request: Request) -> Response:
    check_origin(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with SessionLocal() as db:
            session = db.get(AuthSession, hash_token(token))
            if session is not None:
                db.delete(session)
                db.commit()
    response = Response(status_code=204)
    security.clear_session_cookie(response)
    return response


@router.get("/me")
def me(user: User | None = Depends(get_current_user)) -> dict:
    return {"user": user.to_dict() if user else None}
