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
import ChangePassword from "./pages/ChangePassword";
import Users from "./pages/Users";
import Tests from "./pages/Tests";

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedRoute />}>
        <Route path="/change-password" element={<ChangePassword />} />
        <Route path="/" element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="home" element={<Home />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route
            path="connections"
            element={
              <RequireRole role="admin">
                <Connections />
              </RequireRole>
            }
          />
          <Route
            path="config"
            element={
              <RequireRole role="admin">
                <ConfigEditor />
              </RequireRole>
            }
          />
          <Route
            path="crowdsec"
            element={
              <RequireRole role="admin">
                <CrowdSec />
              </RequireRole>
            }
          />
          <Route
            path="tests"
            element={
              <RequireRole role="admin">
                <Tests />
              </RequireRole>
            }
          />
          <Route
            path="users"
            element={
              <RequireRole role="admin">
                <Users />
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
