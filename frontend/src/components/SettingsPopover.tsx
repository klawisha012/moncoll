import { createEffect, onCleanup, For, Show } from "solid-js";
import { Cog, Sun, Moon, Globe } from "lucide-solid";
import { useSettings } from "../context/SettingsContext";
import type { Lang } from "../i18n/translations";

interface SettingsPopoverProps {
  open: boolean;
  onClose: () => void;
}

export default function SettingsPopover(props: { open: boolean; onClose: () => void }) {
  const settings = useSettings();
  let ref: HTMLDivElement | undefined;

  // Handle outside clicks and Escape key to close the popover
  createEffect(() => {
    if (!props.open) return;

    function handleClick(e: MouseEvent) {
      if (ref && !ref.contains(e.target as Node)) {
        props.onClose();
      }
    }

    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        props.onClose();
      }
    }

    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);

    onCleanup(() => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    });
  });

  return (
    <Show when={props.open}>
      <div class="settings-popover" ref={ref}>
        <div class="settings-popover-header">
          <Cog size={16} />
          <span>{settings.t("settings.title")}</span>
        </div>

        {/* Theme */}
        <div class="settings-group">
          <div class="settings-group-label">{settings.t("settings.theme")}</div>
          <div class="settings-toggle-row">
            <button
              class={`settings-toggle-btn ${settings.theme === "dark" ? "active" : ""}`}
              onClick={settings.toggleTheme}
              title={settings.t("settings.theme.dark")}
            >
              <Moon size={15} />
              <span>{settings.t("settings.theme.dark")}</span>
            </button>
            <button
              class={`settings-toggle-btn ${settings.theme === "light" ? "active" : ""}`}
              onClick={settings.toggleTheme}
              title={settings.t("settings.theme.light")}
            >
              <Sun size={15} />
              <span>{settings.t("settings.theme.light")}</span>
            </button>
          </div>
        </div>

        {/* Language */}
        <div class="settings-group">
          <div class="settings-group-label">{settings.t("settings.language")}</div>
          <div class="settings-toggle-row">
            <For each={["en", "ru"] as Lang[]}>
              {(l) => (
                <button
                  class={`settings-toggle-btn ${settings.lang === l ? "active" : ""}`}
                  onClick={() => settings.setLang(l)}
                >
                  <Globe size={15} />
                  <span>{settings.t(`settings.language.${l}`)}</span>
                </button>
              )}
            </For>
          </div>
        </div>
      </div>
    </Show>
  );
}
