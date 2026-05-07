import { useRef, useEffect } from "react";
import { Cog, Sun, Moon, Globe } from "lucide-react";
import { useSettings } from "../context/SettingsContext";
import type { Lang } from "../i18n/translations";

interface SettingsPopoverProps {
  open: boolean;
  onClose: () => void;
}

export default function SettingsPopover({ open, onClose }: SettingsPopoverProps) {
  const { theme, toggleTheme, lang, setLang, t } = useSettings();
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open, onClose]);

  // Close on Escape
  useEffect(() => {
    if (!open) return;
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="settings-popover" ref={ref}>
      <div className="settings-popover-header">
        <Cog size={16} />
        <span>{t("settings.title")}</span>
      </div>

      {/* Theme */}
      <div className="settings-group">
        <div className="settings-group-label">{t("settings.theme")}</div>
        <div className="settings-toggle-row">
          <button
            className={`settings-toggle-btn ${theme === "dark" ? "active" : ""}`}
            onClick={toggleTheme}
            title={t("settings.theme.dark")}
          >
            <Moon size={15} />
            <span>{t("settings.theme.dark")}</span>
          </button>
          <button
            className={`settings-toggle-btn ${theme === "light" ? "active" : ""}`}
            onClick={toggleTheme}
            title={t("settings.theme.light")}
          >
            <Sun size={15} />
            <span>{t("settings.theme.light")}</span>
          </button>
        </div>
      </div>

      {/* Language */}
      <div className="settings-group">
        <div className="settings-group-label">{t("settings.language")}</div>
        <div className="settings-toggle-row">
          {(["en", "ru"] as Lang[]).map((l) => (
            <button
              key={l}
              className={`settings-toggle-btn ${lang === l ? "active" : ""}`}
              onClick={() => setLang(l)}
            >
              <Globe size={15} />
              <span>{t(`settings.language.${l}`)}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
