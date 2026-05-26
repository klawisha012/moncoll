import { render } from "solid-js/web";
import { Router } from "@solidjs/router";
import { SettingsProvider } from "./context/SettingsContext";
import { AuthProvider } from "./context/AuthContext";
import { GlobalFiltersProvider } from "./context/GlobalFiltersContext";
import App from "./App";
import "leaflet/dist/leaflet.css";
import "./index.css";

const root = document.getElementById("root");

if (root) {
  render(
    () => (
      <SettingsProvider>
        <AuthProvider>
          <GlobalFiltersProvider>
            <App />
          </GlobalFiltersProvider>
        </AuthProvider>
      </SettingsProvider>
    ),
    root
  );
}
