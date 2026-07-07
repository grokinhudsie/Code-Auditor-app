"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  loginWithPasskey,
  registerPasskey,
  requestEmailCode,
  verifyEmailCode,
} from "@/lib/auth";

const OAUTH_ERRORS: Record<string, string> = {
  oauth_state: "GitHub sign-in expired or was tampered with. Try again.",
  github_token: "GitHub didn't accept the sign-in. Try again.",
  github_unreachable: "Couldn't reach GitHub. Try again in a minute.",
  github_email_unverified:
    "Your GitHub account has no verified primary email. Verify it on GitHub first.",
};

type Mode = "signin" | "signup";
type SignupStep = "email" | "code";

function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = safeNext(searchParams.get("next"));
  const oauthError = searchParams.get("error");

  const [mode, setMode] = useState<Mode>("signin");
  const [step, setStep] = useState<SignupStep>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(
    oauthError ? (OAUTH_ERRORS[oauthError] ?? "Sign-in failed. Try again.") : null
  );
  const [busy, setBusy] = useState(false);

  function switchMode(m: Mode) {
    setMode(m);
    setStep("email");
    setCode("");
    setError(null);
  }

  async function run(action: () => Promise<void>) {
    setError(null);
    setBusy(true);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  async function onSignIn(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      await loginWithPasskey(email.trim());
      router.push(next);
    });
  }

  async function onRequestCode(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      await requestEmailCode(email.trim());
      setStep("code");
    });
  }

  async function onVerifyAndRegister(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      const token = await verifyEmailCode(email.trim(), code.trim());
      await registerPasskey(token);
      router.push(next);
    });
  }

  const inputClass =
    "w-full rounded-md border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-neutral-900 dark:border-neutral-700 dark:bg-neutral-900 dark:focus:border-neutral-100";
  const primaryClass =
    "w-full rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-50 dark:bg-neutral-100 dark:text-neutral-900";
  const tabClass = (active: boolean) =>
    `rounded-md px-3 py-1.5 text-sm font-medium ${
      active
        ? "bg-neutral-900 text-white dark:bg-neutral-100 dark:text-neutral-900"
        : "text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100"
    }`;

  return (
    <main className="mx-auto flex w-full max-w-sm flex-1 flex-col justify-center px-6">
      <h1 className="text-2xl font-bold tracking-tight">Sign in to VulnScan</h1>
      <p className="mt-2 text-sm text-neutral-500">
        Accounts keep a history of your scans. Scanning without an account
        still works — you just don&apos;t get history.
      </p>

      <a
        href={`/api/auth/github/start?next=${encodeURIComponent(next)}`}
        className="mt-8 block rounded-md border border-neutral-300 px-4 py-2 text-center text-sm font-medium hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
      >
        Continue with GitHub
      </a>

      <div className="my-6 flex items-center gap-3 text-xs text-neutral-400">
        <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
        or use a passkey
        <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
      </div>

      <div className="mb-3 flex gap-1">
        <button type="button" onClick={() => switchMode("signin")} className={tabClass(mode === "signin")}>
          Sign in
        </button>
        <button type="button" onClick={() => switchMode("signup")} className={tabClass(mode === "signup")}>
          Create account
        </button>
      </div>

      {mode === "signin" && (
        <form onSubmit={onSignIn} className="space-y-2">
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className={inputClass}
          />
          <button type="submit" disabled={busy} className={primaryClass}>
            {busy ? "Waiting for passkey…" : "Sign in with passkey"}
          </button>
        </form>
      )}

      {mode === "signup" && step === "email" && (
        <form onSubmit={onRequestCode} className="space-y-2">
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className={inputClass}
          />
          <button type="submit" disabled={busy} className={primaryClass}>
            {busy ? "Sending…" : "Email me a code"}
          </button>
        </form>
      )}

      {mode === "signup" && step === "code" && (
        <form onSubmit={onVerifyAndRegister} className="space-y-2">
          <p className="text-sm text-neutral-500">
            We sent a 6-digit code to <b>{email.trim()}</b>. Enter it, then
            your browser will ask you to create a passkey.
          </p>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]{6}"
            required
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="123456"
            className={inputClass}
          />
          <button type="submit" disabled={busy} className={primaryClass}>
            {busy ? "Verifying…" : "Verify and create passkey"}
          </button>
          <button
            type="button"
            onClick={() => setStep("email")}
            className="w-full text-xs text-neutral-500 hover:underline"
          >
            Use a different email
          </button>
        </form>
      )}

      {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
