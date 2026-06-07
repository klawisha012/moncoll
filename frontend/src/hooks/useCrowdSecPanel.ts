import { createSignal, createEffect } from "solid-js";
import {
  api,
  type CrowdSecStatus,
  type DecisionItem,
  type ScenarioInfo,
  type AlertItem,
  type Connection,
} from "../api/client";

export interface ManualBlockLog {
  timestamp: string;
  action: string;
  ip: string;
  duration: string;
  reason: string;
  source: string;
}

export interface HubScenario {
  name: string;
  description: string;
  author: string;
  labels: string[];
  installed: boolean;
}

export interface ToastState {
  message: string;
  type: "success" | "error" | "info";
}

export interface BlockRequest {
  ip: string;
  duration: string;
  reason: string;
  connectionIds: number[];
}

type Translate = (key: string, vars?: Record<string, string | number>) => string;

export interface CrowdSecPanelInputs {
  connectionId: () => number | null;
  selectedHours: () => number;
  isAlertsOpen: () => boolean;
  t: Translate;
}

/**
 * Owns all CrowdSec data fetching, mutation actions, and the resulting
 * loading/toast state. The page component keeps only presentation and form
 * state, calling these actions and rendering the returned accessors — so
 * "talk to the CrowdSec API" lives here and "render the panels" lives there.
 */
export function useCrowdSecPanel(inputs: CrowdSecPanelInputs) {
  const { t } = inputs;

  const [status, setStatus] = createSignal<CrowdSecStatus | null>(null);
  const [decisions, setDecisions] = createSignal<DecisionItem[]>([]);
  const [scenarios, setScenarios] = createSignal<ScenarioInfo[]>([]);
  const [hubScenarios, setHubScenarios] = createSignal<HubScenario[]>([]);
  const [manualLog, setManualLog] = createSignal<ManualBlockLog[]>([]);
  const [alerts, setAlerts] = createSignal<AlertItem[]>([]);
  const [connections, setConnections] = createSignal<Connection[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [actionLoading, setActionLoading] = createSignal<string | null>(null);
  const [serviceEnabled, setServiceEnabled] = createSignal(true);
  const [toast, setToast] = createSignal<ToastState | null>(null);

  function showToast(message: string, type: ToastState["type"]) {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  }

  const reload = async () => {
    setLoading(true);
    try {
      const connId = inputs.connectionId();
      const hours = inputs.selectedHours();
      const [s, d, sc, ml, svc, conns] = await Promise.all([
        api.getCrowdSecStatus(connId),
        api.getCrowdSecDecisions(connId),
        api.getCrowdSecScenarios(),
        api.getCrowdSecManualBlocks(50, hours),
        api.getCrowdSecServiceStatus().catch(() => ({ enabled: true })),
        api.getConnections().catch(() => [] as Connection[]),
      ]);
      setStatus(s);
      setDecisions(d);
      setScenarios(sc);
      setManualLog(ml);
      setServiceEnabled(svc.enabled);
      setConnections(conns);
    } catch {
      showToast(t("crowdsec.error.loadFailed"), "error");
    } finally {
      setLoading(false);
    }
  };

  async function loadAlerts() {
    try {
      const items = await api.getCrowdSecAlerts(inputs.selectedHours());
      setAlerts(items);
    } catch (e: any) {
      showToast(e.message, "error");
    }
  }

  async function loadHubScenarios() {
    setActionLoading("hub");
    try {
      const items = await api.getCrowdSecScenarioHub();
      setHubScenarios(items);
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  // Refetch page data when the selected connection or time window changes.
  createEffect(() => {
    inputs.connectionId();
    inputs.selectedHours();
    void reload();
  });

  // Refresh the alerts panel when the time window changes, but only while the
  // user actually has that panel open.
  createEffect(() => {
    inputs.selectedHours();
    if (inputs.isAlertsOpen()) void loadAlerts();
  });

  // Returns true on success so the caller can clear its form.
  async function block(req: BlockRequest): Promise<boolean> {
    setActionLoading("block");
    try {
      const payload: any = {
        ip: req.ip,
        duration: req.duration,
        reason: req.reason,
        type: "ban",
      };
      if (req.connectionIds.length > 0) {
        payload.connection_ids = req.connectionIds;
      }
      const result = await api.addCrowdSecDecision(payload);
      if (result.success) {
        const domainInfo =
          req.connectionIds.length > 0
            ? ` on ${req.connectionIds.length} domain(s)`
            : " on all domains";
        showToast(t("crowdsec.toast.ipBlocked", { ip: req.ip, domainInfo }), "success");
        void reload();
        return true;
      }
      showToast(result.message || t("crowdsec.toast.blockFailed"), "error");
      return false;
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.blockFailed"), "error");
      return false;
    } finally {
      setActionLoading(null);
    }
  }

  async function unblock(ip: string) {
    setActionLoading(`unblock-${ip}`);
    try {
      const result = await api.deleteCrowdSecDecision(ip);
      if (result.success) {
        showToast(t("crowdsec.toast.ipUnblocked", { ip }), "success");
        void reload();
      } else {
        showToast(result.message || t("crowdsec.toast.unblockFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.unblockFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function deleteAllDecisions() {
    setActionLoading("deleteAll");
    try {
      const result = await api.deleteAllCrowdSecDecisions();
      if (result.success) {
        showToast(t("crowdsec.toast.allRemoved"), "success");
        void reload();
      } else {
        showToast(result.message || t("crowdsec.toast.removeAllFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.removeAllFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function installScenario(name: string) {
    setActionLoading(`install-${name}`);
    try {
      const result = await api.installCrowdSecScenario(name);
      showToast(
        result.success
          ? t("crowdsec.toast.scenarioInstalled")
          : result.message || t("crowdsec.toast.scenarioInstallFailed"),
        result.success ? "success" : "error",
      );
      void reload();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function removeScenario(name: string) {
    setActionLoading(`remove-${name}`);
    try {
      const result = await api.removeCrowdSecScenario(name);
      showToast(
        result.success
          ? t("crowdsec.toast.scenarioRemoved")
          : result.message || t("crowdsec.toast.scenarioRemoveFailed"),
        result.success ? "success" : "error",
      );
      void reload();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function toggleScenario(name: string) {
    setActionLoading(`toggle-${name}`);
    try {
      const result = await api.toggleCrowdSecScenario(name);
      showToast(
        result.success
          ? result.enabled
            ? t("crowdsec.toast.scenarioEnabled")
            : t("crowdsec.toast.scenarioDisabled")
          : result.message || t("crowdsec.toast.toggleFailed"),
        result.success ? "success" : "error",
      );
      void reload();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function toggleService() {
    const target = !serviceEnabled();
    setActionLoading("toggleService");
    try {
      const result = await api.toggleCrowdSecService(target);
      if (result.success) {
        showToast(
          result.enabled
            ? t("crowdsec.toast.serviceEnabled")
            : t("crowdsec.toast.serviceDisabled"),
          "success",
        );
        setServiceEnabled(result.enabled);
        void reload();
      } else {
        showToast(result.message || t("crowdsec.toast.serviceToggleFailed"), "error");
      }
    } catch (e: any) {
      showToast(e.message || t("crowdsec.toast.serviceToggleFailed"), "error");
    } finally {
      setActionLoading(null);
    }
  }

  async function reloadEngine() {
    setActionLoading("reload");
    try {
      const result = await api.reloadCrowdSec();
      showToast(
        result.success
          ? t("crowdsec.toast.reloaded")
          : result.message || t("crowdsec.toast.reloadFailed"),
        result.success ? "success" : "error",
      );
      void reload();
    } catch (e: any) {
      showToast(e.message, "error");
    } finally {
      setActionLoading(null);
    }
  }

  return {
    status,
    decisions,
    scenarios,
    hubScenarios,
    manualLog,
    alerts,
    connections,
    loading,
    actionLoading,
    serviceEnabled,
    toast,
    showToast,
    loadAlerts,
    loadHubScenarios,
    block,
    unblock,
    deleteAllDecisions,
    installScenario,
    removeScenario,
    toggleScenario,
    toggleService,
    reloadEngine,
  };
}
