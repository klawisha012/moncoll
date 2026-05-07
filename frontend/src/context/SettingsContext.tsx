import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import type { Lang } from "../i18n/translations";
import { t as translate } from "../i18n/translations";

type Theme = "dark" | "light";

interface SettingsContextValue {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (key: string) => string;
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
  return "dark";
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

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(loadTheme);
  const [lang, setLangState] = useState<Lang>(loadLang);

  // Apply theme on mount and when changed
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t);
    try {
      localStorage.setItem(STORAGE_THEME, t);
    } catch {
      // ignore
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setTheme(theme === "dark" ? "light" : "dark");
  }, [theme, setTheme]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem(STORAGE_LANG, l);
    } catch {
      // ignore
    }
  }, []);

  const t = useCallback((key: string) => translate(lang, key), [lang]);

  return (
    <SettingsContext.Provider value={{ theme, setTheme, toggleTheme, lang, setLang, t }}>
      {children}
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
