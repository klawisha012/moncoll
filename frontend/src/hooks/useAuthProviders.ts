import { useCallback, useEffect, useState } from "react";
import { api, type ProvidersResponse } from "../api/client";

/**
 * Fetch /api/auth/providers with retry-on-failure + refetch on tab focus.
 *
 * Why: the original single-shot fetch failed silently when the backend was
 * mid-restart (connection refused → .catch(() => null)). The state stayed
 * `null`, the OAuth buttons looked enabled but clicks silently returned
 * because `!providers?.[provider]` was always true. Now we keep retrying
 * with backoff and re-poll whenever the tab regains focus, so the buttons
 * become usable as soon as the backend is back.
 */
const RETRY_DELAYS_MS = [500, 1500, 3000, 6000];

export function useAuthProviders(): ProvidersResponse | null {
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);

  const fetchOnce = useCallback(async () => {
    try {
      const data = await api.auth.getProviders();
      setProviders(data);
      return true;
    } catch {
      return false;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let attempt = 0;
    const run = async () => {
      while (!cancelled) {
        const ok = await fetchOnce();
        if (ok || cancelled) return;
        const delay = RETRY_DELAYS_MS[Math.min(attempt, RETRY_DELAYS_MS.length - 1)];
        attempt += 1;
        await new Promise((r) => setTimeout(r, delay));
      }
    };
    void run();

    const onVisible = () => {
      if (document.visibilityState === "visible") {
        attempt = 0;
        void fetchOnce();
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      cancelled = true;
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [fetchOnce]);

  return providers;
}
