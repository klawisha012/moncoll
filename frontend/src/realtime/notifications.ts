import { createSignal } from "solid-js";
import { api } from "../api/client";

const [unreadCount, setUnreadCount] = createSignal(0);
export { unreadCount };

let inflight = false;
export async function refreshUnread() {
  if (inflight) return;
  inflight = true;
  try {
    setUnreadCount(await api.notifications.unreadCount());
  } catch {
    // leave previous count on error
  } finally {
    inflight = false;
  }
}
