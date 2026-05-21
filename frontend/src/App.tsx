import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminOnly from "./components/AdminOnly";
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
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="monitoring" element={<Monitoring />} />
          <Route
            path="connections"
            element={
              <AdminOnly>
                <Connections />
              </AdminOnly>
            }
          />
          <Route
            path="config"
            element={
              <AdminOnly>
                <ConfigEditor />
              </AdminOnly>
            }
          />
          <Route
            path="crowdsec"
            element={
              <AdminOnly>
                <CrowdSec />
              </AdminOnly>
            }
          />
          <Route
            path="tests"
            element={
              <AdminOnly>
                <Tests />
              </AdminOnly>
            }
          />
          <Route
            path="users"
            element={
              <AdminOnly>
                <Users />
              </AdminOnly>
            }
          />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}

export default App;
