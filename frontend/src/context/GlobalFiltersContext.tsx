import {
  createContext,
  useContext,
  createSignal,
  createEffect,
  createMemo,
  onCleanup,
  type JSX,
} from "solid-js";
import { api } from "../api/client";
import { useAuth } from "./AuthContext";
import type { Connection } from "../api/client";

export type TimeUnit = "minutes" | "hours" | "days";

export const TIME_UNIT_MULTIPLIERS: Record<TimeUnit, number> = {
  minutes: 1 / 60,
  hours: 1,
  days: 24,
};

const STORAGE_KEY = "waf:globalFilters:v1";
const MAX_HOURS = 8760;

interface PersistedShape {
  connectionId: number | null;
  timeValue: number;
  timeUnit: TimeUnit;
}

const DEFAULTS: PersistedShape = {
  connectionId: null,
  timeValue: 24,
  timeUnit: "hours",
};

function loadPersisted(): PersistedShape {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<PersistedShape>;
    return {
      connectionId:
        typeof parsed.connectionId === "number" ? parsed.connectionId : null,
      timeValue:
        typeof parsed.timeValue === "number" && parsed.timeValue >= 1
          ? parsed.timeValue
          : DEFAULTS.timeValue,
      timeUnit:
        parsed.timeUnit === "minutes" ||
        parsed.timeUnit === "hours" ||
        parsed.timeUnit === "days"
          ? parsed.timeUnit
          : DEFAULTS.timeUnit,
    };
  } catch {
    return DEFAULTS;
  }
}

interface GlobalFiltersValue {
  connectionId: number | null;
  setConnectionId: (id: number | null) => void;
  timeValue: number;
  setTimeValue: (v: number) => void;
  timeUnit: TimeUnit;
  setTimeUnit: (u: TimeUnit) => void;
  selectedHours: number;
  connections: Connection[];
  setConnections: (cs: Connection[]) => void;
}

const Ctx = createContext<GlobalFiltersValue | null>(null);

export function GlobalFiltersProvider(props: { children: JSX.Element }) {
  const initial = loadPersisted();
  const auth = useAuth();
  
  const [connectionId, setConnectionIdState] = createSignal<number | null>(
    initial.connectionId,
  );
  const [timeValue, setTimeValueState] = createSignal<number>(initial.timeValue);
  const [timeUnit, setTimeUnitState] = createSignal<TimeUnit>(initial.timeUnit);
  const [connections, setConnections] = createSignal<Connection[]>([]);
  const [fetched, setFetched] = createSignal(false);

  // Globally fetch connections for logged-in clients
  createEffect(() => {
    const usr = auth.user;
    if (!usr) return;
    if (usr.platform_role !== "client") return;
    if (fetched()) return;

    let cancelled = false;
    api
      .getConnections()
      .then((cs) => {
        if (!cancelled) {
          setConnections(cs);
          setFetched(true);
        }
      })
      .catch(() => {
        if (!cancelled) setFetched(true);
      });

    onCleanup(() => {
      cancelled = true;
    });
  });

  createEffect(() => {
    try {
      const snapshot: PersistedShape = {
        connectionId: connectionId(),
        timeValue: timeValue(),
        timeUnit: timeUnit(),
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
    } catch {
      // localStorage blocked — fine, fall back to in-memory.
    }
  });

  const setConnectionId = (id: number | null) => {
    setConnectionIdState(id);
  };
  const setTimeValue = (v: number) => {
    if (Number.isFinite(v) && v >= 1) setTimeValueState(Math.floor(v));
  };
  const setTimeUnit = (u: TimeUnit) => {
    setTimeUnitState(u);
  };

  const selectedHours = createMemo(() => {
    const m = TIME_UNIT_MULTIPLIERS[timeUnit()] ?? 1;
    const h = timeValue() * m;
    return Math.min(MAX_HOURS, Math.max(1 / 60, +h.toFixed(4)));
  });

  const value: GlobalFiltersValue = {
    get connectionId() {
      return connectionId();
    },
    setConnectionId,
    get timeValue() {
      return timeValue();
    },
    setTimeValue,
    get timeUnit() {
      return timeUnit();
    },
    setTimeUnit,
    get selectedHours() {
      return selectedHours();
    },
    get connections() {
      return connections();
    },
    setConnections,
  };

  return <Ctx.Provider value={value}>{props.children}</Ctx.Provider>;
}

export function useGlobalFilters(): GlobalFiltersValue {
  const ctx = useContext(Ctx);
  if (!ctx)
    throw new Error("useGlobalFilters must be used within GlobalFiltersProvider");
  return ctx;
}
