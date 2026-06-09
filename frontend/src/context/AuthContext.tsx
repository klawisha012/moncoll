import {
  createContext,
  useContext,
  createSignal,
  onMount,
  onCleanup,
  type JSX,
} from "solid-js";
import { api, type SignupResponse, type User } from "../api/client";

export type { User };

export interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (
    email: string,
    password: string,
    captchaToken: string,
    totpCode?: string,
    keepCurrent?: boolean,
  ) => Promise<{ user: User } | { totp_required: true } | { enrol_required: true }>;
  signup: (
    email: string,
    password: string,
    tenantName: string,
    captchaToken: string,
    displayName?: string,
  ) => Promise<SignupResponse>;
  oauthStart: (
    provider: "google" | "github",
    intent: "signup" | "login",
    tenantName?: string,
  ) => void;
  logout: (all?: boolean) => Promise<void>;
  switchAccount: (userId: number) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider(props: { children: JSX.Element }) {
  const [user, setUser] = createSignal<User | null>(null);
  const [loading, setLoading] = createSignal(true);

  const refresh = async () => {
    const me = await api.auth.me();
    setUser(me);
  };

  onMount(() => {
    let cancelled = false;
    (async () => {
      try {
        const me = await api.auth.me();
        if (!cancelled) setUser(me);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    const handler = () => setUser(null);
    window.addEventListener("auth:unauthorized", handler);

    onCleanup(() => {
      cancelled = true;
      window.removeEventListener("auth:unauthorized", handler);
    });
  });

  const login = async (
    email: string,
    password: string,
    captchaToken: string,
    totpCode?: string,
    keepCurrent?: boolean,
  ) => {
    const resp = await api.auth.login(email, password, captchaToken, totpCode, keepCurrent);
    if ("user" in resp) {
      setUser(resp.user);
    }
    return resp;
  };

  const signup = async (
    email: string,
    password: string,
    tenantName: string,
    captchaToken: string,
    displayName?: string,
  ) => {
    return api.auth.signup(email, password, tenantName, captchaToken, displayName);
  };

  const oauthStart = (
    provider: "google" | "github",
    intent: "signup" | "login",
    tenantName?: string,
  ) => {
    const params = new URLSearchParams({ intent });
    if (tenantName) params.set("tenant_name", tenantName);
    window.location.href = `/api/auth/oauth/${provider}/start?${params.toString()}`;
  };

  const logout = async (all?: boolean) => {
    try {
      await api.auth.logout(all);
    } finally {
      setUser(null);
    }
  };

  const switchAccount = async (userId: number) => {
    const u = await api.auth.switchAccount(userId);
    setUser(u);
  };

  const changePassword = async (currentPassword: string, newPassword: string) => {
    const updated = await api.auth.changePassword(currentPassword, newPassword);
    if (updated) setUser(updated);
  };

  // Expose getters so that property access remains reactive inside SolidJS components
  const value: AuthContextValue = {
    get user() {
      return user();
    },
    get loading() {
      return loading();
    },
    login,
    signup,
    oauthStart,
    logout,
    switchAccount,
    changePassword,
    refresh,
  };

  return (
    <AuthContext.Provider value={value}>
      {props.children}
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
