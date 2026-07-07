"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { getMe, logout, type AuthUser } from "@/lib/auth";

export function Header() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loaded, setLoaded] = useState(false);
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    let active = true;
    getMe()
      .then((u) => {
        if (active) setUser(u);
      })
      .finally(() => {
        if (active) setLoaded(true);
      });
    return () => {
      active = false;
    };
  }, [pathname]);

  async function onLogout() {
    try {
      await logout();
    } finally {
      setUser(null);
      router.push("/");
    }
  }

  return (
    <header className="flex items-center justify-between px-6 py-3 text-sm">
      <Link href="/" className="font-semibold tracking-tight">
        VulnScan
      </Link>
      {loaded && (
        <nav className="flex items-center gap-4">
          {user ? (
            <>
              <Link href="/history" className="text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100">
                History
              </Link>
              <Link
                href="/account"
                className="flex items-center gap-2 text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100"
              >
                {user.avatar_url && (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img
                    src={user.avatar_url}
                    alt=""
                    className="h-5 w-5 rounded-full"
                  />
                )}
                {user.display_name ?? user.email}
              </Link>
              <button
                type="button"
                onClick={onLogout}
                className="text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100"
              >
                Sign out
              </button>
            </>
          ) : (
            pathname !== "/login" && (
              <Link href="/login" className="text-neutral-500 hover:text-neutral-900 dark:hover:text-neutral-100">
                Sign in
              </Link>
            )
          )}
        </nav>
      )}
    </header>
  );
}
