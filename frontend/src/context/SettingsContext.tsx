import { createContext, useContext, createSignal, createEffect, type JSX } from "solid-js";
import type { Lang } from "../i18n/translations";
import { t as translate } from "../i18n/translations";

type Theme = "dark" | "light";

interface SettingsContextValue {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

const STORAGE_THEME = "waf-theme";
const STORAGE_LANG = "waf-lang";

function detectBrowserLang(): Lang {
  const navLang = navigator.language?.slice(0, 2).toLowerCase();
  return navLang === "ru" ? "ru" : "en";
}

function loadTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_THEME);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // localStorage unavailable
  }
  return "light";
}

function loadLang(): Lang {
  try {
    const stored = localStorage.getItem(STORAGE_LANG);
    if (stored === "en" || stored === "ru") return stored;
  } catch {
    // localStorage unavailable
  }
  return detectBrowserLang();
}

function applyTheme(theme: Theme) {
  document.documentElement.setAttribute("data-theme", theme);
}

export function SettingsProvider(props: { children: JSX.Element }) {
  const [theme, setThemeState] = createSignal<Theme>(loadTheme());
  const [lang, setLangState] = createSignal<Lang>(loadLang());

  // Apply theme when changed reactively
  createEffect(() => {
    applyTheme(theme());
  });

  const setTheme = (t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem(STORAGE_THEME, t);
    } catch {
      // ignore
    }
  };

  const toggleTheme = () => {
    setTheme(theme() === "dark" ? "light" : "dark");
  };

  const setLang = (l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem(STORAGE_LANG, l);
    } catch {
      // ignore
    }
  };

  const t = (key: string, vars?: Record<string, string | number>) => {
    return translate(lang(), key, vars);
  };

  const value: SettingsContextValue = {
    get theme() {
      return theme();
    },
    get lang() {
      return lang();
    },
    setTheme,
    toggleTheme,
    setLang,
    t,
  };

  return (
    <SettingsContext.Provider value={value}>
      {props.children}
    </SettingsContext.Provider>
  );
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) {
    throw new Error("useSettings must be used within a SettingsProvider");
  }
  return ctx;
}
