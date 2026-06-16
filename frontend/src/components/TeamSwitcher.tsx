import { createSignal, onMount, For, Show } from "solid-js";
import { Users2, ChevronDown } from "lucide-solid";
import { api, type Team } from "../api/client";
import { useSettings } from "../context/SettingsContext";

// Active-team picker. Lives at the top of the Team page (it used to be an
// unstyled native <select> wedged into the sidebar). Only renders when the
// user belongs to more than one team; switching reloads the app so every view
// re-fetches under the newly active tenant.
export default function TeamSwitcher() {
  const settings = useSettings();
  const [teams, setTeams] = createSignal<Team[]>([]);
  const load = async () => {
    try {
      setTeams(await api.teams.list());
    } catch {
      setTeams([]);
    }
  };
  onMount(() => void load());

  const onChange = async (e: Event) => {
    const tenantId = Number((e.currentTarget as HTMLSelectElement).value);
    try {
      await api.teams.switch(tenantId);
      window.location.reload();
    } catch {
      /* ignore — stay on the current team */
    }
  };

  return (
    <Show when={teams().length > 1}>
      <div class="team-switcher">
        <Users2 class="team-switcher-icon" size={18} aria-hidden="true" />
        <label class="team-switcher-label" for="team-switcher-select">
          {settings.t("team.switch")}
        </label>
        <div class="team-switcher-control">
          <select
            id="team-switcher-select"
            class="team-switcher-select"
            title={settings.t("team.switch")}
            onChange={onChange}
          >
            <For each={teams()}>
              {(tm) => (
                <option value={tm.tenant_id} selected={tm.active}>
                  {tm.display_name}
                </option>
              )}
            </For>
          </select>
          <ChevronDown class="team-switcher-chevron" size={16} aria-hidden="true" />
        </div>
      </div>
    </Show>
  );
}
