import { startAuthentication, startRegistration } from "@simplewebauthn/browser";

export type AuthUser = {
  id: string;
  email: string;
  display_name: string | null;
  avatar_url: string | null;
};

async function post(path: string, body?: object): Promise<Response> {
  return fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : null,
  });
}

async function orThrow(res: Response): Promise<Response> {
  if (!res.ok) {
    const detail = await res.json().catch(() => null);
    throw new Error(detail?.detail ?? `Request failed (${res.status})`, {
      cause: res.status,
    });
  }
  return res;
}

export async function getMe(): Promise<AuthUser | null> {
  const res = await fetch("/api/auth/me", { cache: "no-store" });
  if (!res.ok) return null;
  const data = await res.json();
  return data.user ?? null;
}

export async function logout(): Promise<void> {
  await orThrow(await post("/api/auth/logout"));
}

export async function requestEmailCode(email: string): Promise<void> {
  await orThrow(await post("/api/auth/email/code", { email }));
}

export async function verifyEmailCode(
  email: string,
  code: string
): Promise<string> {
  const res = await orThrow(await post("/api/auth/email/verify", { email, code }));
  const data = await res.json();
  return data.registration_token;
}

// With a registrationToken (from email verification): signup or account
// recovery. Without one: adds a passkey to the logged-in session's account.
export async function registerPasskey(
  registrationToken?: string
): Promise<AuthUser> {
  const tokenField = registrationToken
    ? { registration_token: registrationToken }
    : {};
  const optionsRes = await orThrow(
    await post("/api/auth/webauthn/register/options", { ...tokenField })
  );
  const credential = await startRegistration({
    optionsJSON: await optionsRes.json(),
  });
  const verifyRes = await orThrow(
    await post("/api/auth/webauthn/register/verify", {
      ...tokenField,
      credential,
    })
  );
  return (await verifyRes.json()).user;
}

export type Passkey = {
  id: string;
  created_at: string | null;
  last_used_at: string | null;
  transports: string[] | null;
};

export async function listPasskeys(): Promise<Passkey[]> {
  const res = await orThrow(
    await fetch("/api/auth/webauthn/credentials", { cache: "no-store" })
  );
  return (await res.json()).passkeys;
}

export async function deletePasskey(id: string): Promise<void> {
  await orThrow(
    await fetch(`/api/auth/webauthn/credentials/${encodeURIComponent(id)}`, {
      method: "DELETE",
    })
  );
}

export async function revokeOtherSessions(): Promise<number> {
  const res = await orThrow(await post("/api/auth/sessions/revoke-others"));
  return (await res.json()).revoked;
}

export async function loginWithPasskey(email: string): Promise<AuthUser> {
  const optionsRes = await orThrow(
    await post("/api/auth/webauthn/login/options", { email })
  );
  const credential = await startAuthentication({
    optionsJSON: await optionsRes.json(),
  });
  const verifyRes = await orThrow(
    await post("/api/auth/webauthn/login/verify", { email, credential })
  );
  return (await verifyRes.json()).user;
}
