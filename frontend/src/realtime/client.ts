/**
 * centrifuge-js wrapper для WAF dashboard.
 *
 * Lifecycle:
 *   1. getConnection() возвращает singleton Centrifuge instance.
 *   2. На каждом connect() центрифуга вызывает getToken — мы дёргаем
 *      backend `/api/realtime/token` (cookie-auth) и отдаём короткий
 *      HMAC-JWT. centrifuge-js сам refresh'ит токен по истечении.
 *   3. Reconnect/backoff/heartbeat — встроены, ничего своего писать
 *      не надо.
 *
 * Подписка через subscribe(channel, onPublication). Возвращает
 * `unsubscribe()` для cleanup в useEffect.
 */
import { Centrifuge, Subscription } from "centrifuge";
import { api } from "../api/client";

// Centrifugo слушает на 8001 (docker-compose маппинг). В проде
// сменишь на /connection/websocket через reverse-proxy.
const getCentrifugoWsUrl = (): string => {
  const envUrl = import.meta.env.VITE_CENTRIFUGO_URL as string | undefined;
  if (envUrl) return envUrl;

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.hostname;
  return `${protocol}//${host}:8001/connection/websocket`;
};

const CENTRIFUGO_WS_URL = getCentrifugoWsUrl();

let _client: Centrifuge | null = null;

function getClient(): Centrifuge {
  if (_client) return _client;

  _client = new Centrifuge(CENTRIFUGO_WS_URL, {
    // centrifuge-js вызывает callback ПЕРЕД connect и при истечении токена.
    // Backend выдаёт TTL=3600s, client refresh'ит сам.
    getToken: async () => {
      const resp = await api.getRealtimeToken();
      return resp.token;
    },
  });

  // Лог в консоль для отладки. В проде убери.
  _client.on("connecting", (ctx) => console.debug("[centrifuge] connecting", ctx));
  _client.on("connected", (ctx) => console.debug("[centrifuge] connected", ctx));
  _client.on("disconnected", (ctx) => console.debug("[centrifuge] disconnected", ctx));
  _client.on("error", (ctx) => console.warn("[centrifuge] error", ctx));

  _client.connect();
  return _client;
}

export interface GeoipMapDelta {
  type: "geoip_map_delta";
  ts: number;
  points: {
    cc: string;
    lat: number;
    lon: number;
    city: string;
    delta: number;
  }[];
}

/**
 * Подписаться на канал. Возвращает функцию unsubscribe — вызывай её в
 * useEffect cleanup чтобы освободить подписку при unmount.
 */
export function subscribe<T>(
  channel: string,
  onPublication: (data: T) => void,
): () => void {
  const client = getClient();
  let sub: Subscription | null = client.getSubscription(channel);
  if (!sub) {
    sub = client.newSubscription(channel);
  }
  const handler = (ctx: { data: T }) => onPublication(ctx.data);
  sub.on("publication", handler);
  if (sub.state !== "subscribed") {
    sub.subscribe();
  }
  return () => {
    sub?.off("publication", handler);
    // Не уничтожаем subscription если её слушают другие хуки — пусть
    // живёт в client cache. Centrifugo сам закроет если никто не слушает.
  };
}
