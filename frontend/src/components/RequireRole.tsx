import { Navigate } from "@solidjs/router";
import { Show, type JSX } from "solid-js";
import { useAuth } from "../context/AuthContext";

type Role = "admin" | "client";

// RequireRole gates a route by platform role. `role` may be a single role or a
// list — a route is allowed when the user's role is in the list. Client routes
// pass ["client", "admin"] because a platform admin is scoped to the system
// tenant server-side (auth interceptor) and views the platform's own site
// through the client tabs; admin-only routes pass just "admin".
export default function RequireRole(props: { role: Role | Role[]; children?: JSX.Element }) {
  const auth = useAuth();

  const allowed = () => {
    const role = auth.user?.platform_role;
    if (!role) return false;
    const allowedRoles = Array.isArray(props.role) ? props.role : [props.role];
    return allowedRoles.includes(role as Role);
  };

  return (
    <Show
      when={auth.user}
      fallback={<Navigate href="/login" />}
    >
      <Show
        when={allowed()}
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
