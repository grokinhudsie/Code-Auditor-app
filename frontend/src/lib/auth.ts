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
    throw new Error(detail?.detail ?? `Request failed (${res.status})`);
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

export async function registerPasskey(
  registrationToken: string
): Promise<AuthUser> {
  const optionsRes = await orThrow(
    await post("/api/auth/webauthn/register/options", {
      registration_token: registrationToken,
    })
  );
  const credential = await startRegistration({
    optionsJSON: await optionsRes.json(),
  });
  const verifyRes = await orThrow(
    await post("/api/auth/webauthn/register/verify", {
      registration_token: registrationToken,
      credential,
    })
  );
  return (await verifyRes.json()).user;
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
