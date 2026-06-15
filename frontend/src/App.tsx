import { Router, Route, Navigate } from "@solidjs/router";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import RequireRole from "./components/RequireRole";
import Landing from "./pages/Landing";
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
import InviteAccept from "./pages/InviteAccept";
import Team from "./pages/Team";
import Notifications from "./pages/Notifications";

export default function App() {
  return (
    <Router>
      {/* Public landing — the marketing front door at "/" */}
      <Route path="/" component={Landing} />

      {/* Public auth routes */}
      <Route path="/login" component={Login} />
      <Route path="/signup" component={Signup} />
      <Route path="/verify-email" component={VerifyEmail} />
      <Route path="/invite/accept" component={InviteAccept} />
      <Route path="/forgot-password" component={ForgotPassword} />
      <Route path="/reset-password" component={ResetPassword} />
      <Route path="/totp-setup" component={TotpSetup} />

      {/* Authenticated routes (pathless ProtectedRoute → pathless Layout) */}
      <Route path="" component={ProtectedRoute}>
        <Route path="/change-password" component={ChangePassword} />

        <Route path="" component={Layout}>
          {/* Admin-only routes */}
          <Route path="monitoring" component={() => (<RequireRole role="admin"><Monitoring /></RequireRole>)} />
          <Route path="clients" component={() => (<RequireRole role="admin"><Clients /></RequireRole>)} />
          <Route path="clients/:id" component={() => (<RequireRole role="admin"><ClientDetail /></RequireRole>)} />

          {/* Client routes */}
          <Route path="home" component={() => (<RequireRole role="client"><Home /></RequireRole>)} />
          <Route path="dashboard" component={() => (<RequireRole role="client"><Dashboard /></RequireRole>)} />
          <Route path="connections" component={() => (<RequireRole role="client"><Connections /></RequireRole>)} />
          <Route path="config" component={() => (<RequireRole role="client"><ConfigEditor /></RequireRole>)} />
          <Route path="crowdsec" component={() => (<RequireRole role="client"><CrowdSec /></RequireRole>)} />
          <Route path="tests" component={() => (<RequireRole role="client"><Tests /></RequireRole>)} />
          <Route path="team" component={() => (<RequireRole role="client"><Team /></RequireRole>)} />
          <Route path="notifications" component={() => (<RequireRole role="client"><Notifications /></RequireRole>)} />
        </Route>
      </Route>

      {/* Catch-all → landing */}
      <Route path="*" component={() => <Navigate href="/" />} />
    </Router>
  );
}
