import { Navigate, useLocation } from "@solidjs/router";
import { Show, type JSX } from "solid-js";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute(props: { children?: JSX.Element }) {
  const auth = useAuth();
  const location = useLocation();

  return (
    <Show
      when={!auth.loading}
      fallback={
        <div
          style={{
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
            "min-height": "100vh",
            color: "var(--text-muted)",
            "font-size": "14px",
          }}
        >
          Loading…
        </div>
      }
    >
      <Show
        when={auth.user}
        fallback={
          <Navigate href="/login" state={{ from: location.pathname }} />
        }
      >
        {props.children}
      </Show>
    </Show>
  );
}
