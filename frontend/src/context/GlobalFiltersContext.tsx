import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
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
  /** Time window in hours (timeValue * multiplier), clamped to [1/60, MAX_HOURS]. */
  selectedHours: number;
  /** All enabled connections for the current tenant. Empty until first load completes. */
  connections: Connection[];
  setConnections: (cs: Connection[]) => void;
}

const Ctx = createContext<GlobalFiltersValue | null>(null);

export function GlobalFiltersProvider({ children }: { children: ReactNode }) {
  const initial = useMemo(loadPersisted, []);
  const [connectionId, setConnectionIdState] = useState<number | null>(
    initial.connectionId,
  );
  const [timeValue, setTimeValueState] = useState<number>(initial.timeValue);
  const [timeUnit, setTimeUnitState] = useState<TimeUnit>(initial.timeUnit);
  const [connections, setConnections] = useState<Connection[]>([]);

  useEffect(() => {
    try {
      const snapshot: PersistedShape = { connectionId, timeValue, timeUnit };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
    } catch {
      // localStorage blocked — fine, fall back to in-memory.
    }
  }, [connectionId, timeValue, timeUnit]);

  const setConnectionId = useCallback((id: number | null) => {
    setConnectionIdState(id);
  }, []);
  const setTimeValue = useCallback((v: number) => {
    if (Number.isFinite(v) && v >= 1) setTimeValueState(Math.floor(v));
  }, []);
  const setTimeUnit = useCallback((u: TimeUnit) => {
    setTimeUnitState(u);
  }, []);

  const selectedHours = useMemo(() => {
    const m = TIME_UNIT_MULTIPLIERS[timeUnit] ?? 1;
    const h = timeValue * m;
    return Math.min(MAX_HOURS, Math.max(1 / 60, +h.toFixed(4)));
  }, [timeValue, timeUnit]);

  const value = useMemo<GlobalFiltersValue>(
    () => ({
      connectionId,
      setConnectionId,
      timeValue,
      setTimeValue,
      timeUnit,
      setTimeUnit,
      selectedHours,
      connections,
      setConnections,
    }),
    [
      connectionId,
      setConnectionId,
      timeValue,
      setTimeValue,
      timeUnit,
      setTimeUnit,
      selectedHours,
      connections,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useGlobalFilters(): GlobalFiltersValue {
  const ctx = useContext(Ctx);
  if (!ctx)
    throw new Error("useGlobalFilters must be used within GlobalFiltersProvider");
  return ctx;
}
