import { createSignal, onMount, For, Show } from "solid-js";
import { api, type Team } from "../api/client";
import { useSettings } from "../context/SettingsContext";

export default function TeamSwitcher() {
  const settings = useSettings();
  const [teams, setTeams] = createSignal<Team[]>([]);
  const load = async () => { try { setTeams(await api.teams.list()); } catch { setTeams([]); } };
  onMount(() => void load());
  const onChange = async (e: Event) => {
    const tenantId = Number((e.currentTarget as HTMLSelectElement).value);
    try { await api.teams.switch(tenantId); window.location.reload(); } catch { /* ignore */ }
  };
  return (
    <Show when={teams().length > 1}>
      <select title={settings.t("team.switch")} onChange={onChange}>
        <For each={teams()}>{(tm) => <option value={tm.tenant_id} selected={tm.active}>{tm.display_name}</option>}</For>
      </select>
    </Show>
  );
}
