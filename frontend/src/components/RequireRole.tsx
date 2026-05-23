import { Navigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../context/AuthContext";

type Role = "admin" | "client";

export default function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (user.platform_role !== role) {
    return <Navigate to={user.platform_role === "admin" ? "/monitoring" : "/home"} replace />;
  }
  return <>{children}</>;
}
