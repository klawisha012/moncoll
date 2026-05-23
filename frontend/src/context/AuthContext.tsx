import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, type User } from "../api/client";

export type { User };

export interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (
    email: string,
    password: string,
    captchaToken: string,
    totpCode?: string,
  ) => Promise<{ user: User } | { totp_required: true } | { enrol_required: true }>;
  signup: (
    email: string,
    password: string,
    tenantName: string,
    captchaToken: string,
    displayName?: string,
  ) => Promise<{ message: string }>;
  oauthStart: (
    provider: "google" | "github",
    intent: "signup" | "login",
    tenantName?: string,
  ) => void;
  logout: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const me = await api.auth.me();
    setUser(me);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const me = await api.auth.me();
        if (!cancelled) setUser(me);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const handler = () => setUser(null);
    window.addEventListener("auth:unauthorized", handler);
    return () => window.removeEventListener("auth:unauthorized", handler);
  }, []);

  const login = useCallback(
    async (
      email: string,
      password: string,
      captchaToken: string,
      totpCode?: string,
    ) => {
      const resp = await api.auth.login(email, password, captchaToken, totpCode);
      if ("user" in resp) {
        setUser(resp.user);
      }
      return resp;
    },
    [],
  );

  const signup = useCallback(
    async (
      email: string,
      password: string,
      tenantName: string,
      captchaToken: string,
      displayName?: string,
    ) => {
      return api.auth.signup(email, password, tenantName, captchaToken, displayName);
    },
    [],
  );

  const oauthStart = useCallback(
    (provider: "google" | "github", intent: "signup" | "login", tenantName?: string) => {
      const params = new URLSearchParams({ provider, intent });
      if (tenantName) params.set("tenant_name", tenantName);
      window.location.href = `/api/auth/oauth/start?${params.toString()}`;
    },
    [],
  );

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      const updated = await api.auth.changePassword(currentPassword, newPassword);
      if (updated) setUser(updated);
    },
    [],
  );

  return (
    <AuthContext.Provider
      value={{ user, loading, login, signup, oauthStart, logout, changePassword, refresh }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
