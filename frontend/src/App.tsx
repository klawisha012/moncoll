import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import RequireRole from "./components/RequireRole";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Connections from "./pages/Connections";
import ConfigEditor from "./pages/ConfigEditor";
import Monitoring from "./pages/Monitoring";
import CrowdSec from "./pages/CrowdSec";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import VerifyEmail from "./pages/VerifyEmail";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import TotpSetup from "./pages/TotpSetup";
import ChangePassword from "./pages/ChangePassword";
import Tests from "./pages/Tests";
import Clients from "./pages/Clients";
import ClientDetail from "./pages/ClientDetail";

function App() {
  return (
    <Routes>
      {/* Public auth routes */}
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/totp-setup" element={<TotpSetup />} />

      {/* Authenticated routes */}
      <Route element={<ProtectedRoute />}>
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="/" element={<Layout />}>
          {/* Admin-only routes */}
          <Route
            path="monitoring"
            element={
              <RequireRole role="admin">
                <Monitoring />
              </RequireRole>
            }
          />
          <Route
            path="clients"
            element={
              <RequireRole role="admin">
                <Clients />
              </RequireRole>
            }
          />
          <Route
            path="clients/:id"
            element={
              <RequireRole role="admin">
                <ClientDetail />
              </RequireRole>
            }
          />

          {/* Client-role routes */}
          <Route index element={<Home />} />
          <Route
            path="home"
            element={
              <RequireRole role="client">
                <Home />
              </RequireRole>
            }
          />
          <Route
            path="dashboard"
            element={
              <RequireRole role="client">
                <Dashboard />
              </RequireRole>
            }
          />
          <Route
            path="connections"
            element={
              <RequireRole role="client">
                <Connections />
              </RequireRole>
            }
          />
          <Route
            path="config"
            element={
              <RequireRole role="client">
                <ConfigEditor />
              </RequireRole>
            }
          />
          <Route
            path="crowdsec"
            element={
              <RequireRole role="client">
                <CrowdSec />
              </RequireRole>
            }
          />
          <Route
            path="tests"
            element={
              <RequireRole role="client">
                <Tests />
              </RequireRole>
            }
          />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
