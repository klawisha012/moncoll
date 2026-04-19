import { useEffect } from "react";

export default function Dashboard() {
  useEffect(() => {
    // No backend data fetching needed - Grafana handles everything
  }, []);

  return (
    <div style={{ height: "calc(100vh - 80px)" }}>
      <div className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>WAF monitoring and analytics powered by Grafana</p>
        </div>
      </div>

      {/* Embedded Grafana dashboard occupying full available space */}
      <div style={{ height: "calc(100vh - 180px)", overflow: "hidden" }}>
        <iframe
          // Grafana is embedded via the /grafana/ proxy path
          src="/grafana/d/waf-nginx-dashboard?orgId=1&refresh=10s"
          style={{ border: "none", width: "100%", height: "100%" }}
          title="Grafana Dashboard"
          sandbox="allow-scripts allow-same-origin"
        />
      </div>
    </div>
  );
}
