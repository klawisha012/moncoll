import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 3000,
    proxy: {
      "/modsecurity": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
      "/angie": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
      "/dashboard": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
    },
  },
});
