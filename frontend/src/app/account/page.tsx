"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  deletePasskey,
  listPasskeys,
  registerPasskey,
  revokeOtherSessions,
  type Passkey,
} from "@/lib/auth";

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "never";
}

export default function AccountPage() {
  const [passkeys, setPasskeys] = useState<Passkey[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const router = useRouter();

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const keys = await listPasskeys();
        if (active) setPasskeys(keys);
      } catch (err) {
        if (!active) return;
        if (err instanceof Error && err.cause === 401) {
          router.push("/login?next=/account");
          return;
        }
        setError(err instanceof Error ? err.message : "Failed to load passkeys");
      }
    })();
    return () => {
      active = false;
    };
  }, [refresh, router]);

  async function run(action: () => Promise<void>) {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  async function onAdd() {
    await run(async () => {
      await registerPasskey();
      setNotice("Passkey added.");
      setRefresh((n) => n + 1);
    });
  }

  async function onDelete(id: string) {
    if (!confirm("Remove this passkey? You won't be able to sign in with it anymore.")) {
      return;
    }
    await run(async () => {
      await deletePasskey(id);
      setNotice("Passkey removed.");
      setRefresh((n) => n + 1);
    });
  }

  async function onRevokeOthers() {
    await run(async () => {
      const n = await revokeOtherSessions();
      setNotice(
        n === 0
          ? "No other sessions were signed in."
          : `Signed out ${n} other session${n === 1 ? "" : "s"}.`
      );
    });
  }

  const buttonClass =
    "rounded border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800";

  return (
    <main className="mx-auto w-full max-w-3xl px-6 py-10">
      <h1 className="text-xl font-semibold">Account</h1>

      <section className="mt-6">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            Passkeys
          </h2>
          <button type="button" onClick={onAdd} disabled={busy} className={buttonClass}>
            {busy ? "…" : "Add a passkey"}
          </button>
        </div>
        <p className="mt-1 text-xs text-neutral-500">
          Register a passkey on each device you sign in from. If you lose one,
          remove it here (or recover your account from the sign-in page).
        </p>

        {passkeys === null && !error && (
          <p className="mt-4 text-sm text-neutral-500">Loading…</p>
        )}

        {passkeys !== null && (
          <ul className="mt-3 divide-y divide-neutral-100 rounded-lg border border-neutral-200 dark:divide-neutral-900 dark:border-neutral-800">
            {passkeys.map((p) => (
              <li key={p.id} className="flex items-center gap-3 px-4 py-3 text-sm">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-xs text-neutral-500">
                    {p.id.slice(0, 12)}…
                  </p>
                  <p className="mt-0.5 text-xs text-neutral-500">
                    Added {formatDate(p.created_at)} · Last used{" "}
                    {formatDate(p.last_used_at)}
                    {p.transports && p.transports.length > 0 && (
                      <> · {p.transports.join(", ")}</>
                    )}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onDelete(p.id)}
                  disabled={busy}
                  className={buttonClass}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="mt-10">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
          Sessions
        </h2>
        <p className="mt-1 text-xs text-neutral-500">
          Signed in somewhere you don&apos;t recognize? Sign out every session
          except this one.
        </p>
        <button
          type="button"
          onClick={onRevokeOthers}
          disabled={busy}
          className={`mt-3 ${buttonClass}`}
        >
          Sign out everywhere else
        </button>
      </section>

      {notice && <p className="mt-4 text-sm text-green-700 dark:text-green-400">{notice}</p>}
      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
    </main>
  );
}
