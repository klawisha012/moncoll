import { Navigate } from "@solidjs/router";
import { Show, type JSX } from "solid-js";
import { useAuth } from "../context/AuthContext";

type Role = "admin" | "client";

export default function RequireRole(props: { role: Role; children?: JSX.Element }) {
  const auth = useAuth();

  return (
    <Show
      when={auth.user}
      fallback={<Navigate href="/login" />}
    >
      <Show
        when={auth.user?.platform_role === props.role}
        fallback={
          <Navigate
            href={auth.user?.platform_role === "admin" ? "/monitoring" : "/home"}
          />
        }
      >
        {props.children}
      </Show>
    </Show>
  );
}
