"""CrowdSec service - manages decisions and scenarios via Docker SDK."""

import json
import logging
import os
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import docker

from .schemas import (
    AlertItem,
    CrowdSecStatus,
    DecisionCreate,
    DecisionItem,
    ScenarioInfo,
)

logger = logging.getLogger(__name__)

CROWDSEC_CONTAINER = "waf-crowdsec-1"
ANGIE_CONTAINER = "waf-angie-1"
BLOCKED_IPS_CONF = "/var/lib/angie/http.d/blocked_ips.list"

# ClickHouse connection from environment
CLICKHOUSE_ENDPOINT = os.getenv("CLICKHOUSE_ENDPOINT", "http://clickhouse:8123")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "logs")

try:
    from clickhouse_driver import Client as CHClient

    _ch_client = CHClient(
        host=CLICKHOUSE_ENDPOINT.replace("http://", "").split(":")[0],
        port=9000,
        user=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DB,
    )
except Exception:
    _ch_client = None
    logger.warning("ClickHouse client not available for CrowdSec audit log")


@lru_cache(maxsize=1)
def _get_container():
    """Get the CrowdSec Docker container object (cached)."""
    client = docker.from_env()
    return client.containers.get(CROWDSEC_CONTAINER)


def _run_cscli(args: list[str]) -> tuple[int, str, str]:
    """Execute cscli command in the CrowdSec container.
    Returns (exit_code, stdout, stderr).
    """
    try:
        container = _get_container()
        exit_code, output = container.exec_run(["cscli", *args])
        stdout = output.decode() if isinstance(output, bytes) else str(output)
        return exit_code, stdout, ""
    except docker.errors.NotFound:
        return 1, "", f"Container '{CROWDSEC_CONTAINER}' not found"
    except Exception as e:
        logger.exception("cscli execution failed")
        return 1, "", str(e)


def _run_cscli_json(args: list[str]) -> dict:
    """Execute cscli with JSON output.

    Some cscli commands (e.g. ``hub list -a``) print status lines
    (``Loaded: …``, ``Unmanaged: …``) before the JSON.  We skip those
    by locating the first ``{`` or ``[`` in the output.
    """
    exit_code, stdout, stderr = _run_cscli([*args, "-o", "json"])
    if exit_code != 0:
        logger.error("cscli failed (exit=%d): %s", exit_code, stderr)
        return {}
    try:
        text = stdout.strip()
        if not text:
            return {}
        # Find first JSON character (skip status lines like "Loaded: …")
        start = 0
        for i, ch in enumerate(text):
            if ch in ("{", "["):
                start = i
                break
        return json.loads(text[start:])
    except json.JSONDecodeError:
        logger.warning("cscli returned non-JSON: %s", stdout[:200])
        return {}


# ── Blocked IPs sync ───────────────────────────────────────

CONNECTIONS_JSON = "/var/lib/angie/connections.json"
CONNECTIONS_D_DIR = "/var/lib/angie/http.d"
BLOCKED_IPS_MAPPING = "/var/lib/angie/blocked_ips_mapping.json"


def _load_connections() -> list[dict]:
    """Load all connections from connections.json."""
    try:
        if not os.path.exists(CONNECTIONS_JSON):
            return []
        with open(CONNECTIONS_JSON) as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        return [c for c in data if isinstance(c, dict)]
    except Exception:
        logger.exception("Failed to load connections.json")
        return []


def _load_connection_ids() -> list[int]:
    """Load enabled connection IDs from connections.json."""
    return [c["id"] for c in _load_connections() if c.get("enabled")]


def _build_domain_to_conn_map() -> dict[str, int]:
    """Build a mapping from domain name to connection ID (first match wins)."""
    mapping: dict[str, int] = {}
    for conn in _load_connections():
        if not conn.get("enabled"):
            continue
        for domain in conn.get("domains", []):
            domain_lower = domain.strip().lower()
            if domain_lower and domain_lower not in mapping:
                mapping[domain_lower] = conn["id"]
    return mapping


def _load_blocked_ips_mapping() -> dict[str, list[int]]:
    """Load IP → connection_ids mapping for manual blocks."""
    try:
        if not os.path.exists(BLOCKED_IPS_MAPPING):
            return {}
        with open(BLOCKED_IPS_MAPPING) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        logger.exception("Failed to load blocked_ips_mapping.json")
        return {}


def _save_blocked_ips_mapping(mapping: dict[str, list[int]]) -> None:
    """Save IP → connection_ids mapping."""
    os.makedirs(os.path.dirname(BLOCKED_IPS_MAPPING), exist_ok=True)
    with open(BLOCKED_IPS_MAPPING, "w") as f:
        json.dump(mapping, f, indent=2)


def _extract_target_hosts_from_alerts(alerts: list) -> dict[str, set[str]]:
    """Extract target_host from CrowdSec alert meta for automatic domain routing.
    Returns {ip_value: {hostname, ...}}.
    """
    result: dict[str, set[str]] = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        source = alert.get("source", {}) or {}
        ip_value = source.get("value", "") if isinstance(source, dict) else ""
        if not ip_value:
            continue
        meta_items = alert.get("meta", []) or []
        if not isinstance(meta_items, list):
            continue
        hosts: set[str] = set()
        for m in meta_items:
            if not isinstance(m, dict):
                continue
            key = (m.get("key") or "").lower()
            val = (m.get("value") or "").strip().lower()
            if key in ("target_host", "http_host", "target_fqdn", "host") and val:
                hosts.add(val)
        if hosts:
            result.setdefault(ip_value, set()).update(hosts)
    return result


def _resolve_ip_connections(
    ip_value: str,
    manual_mapping: dict[str, list[int]],
    target_hosts: dict[str, set[str]],
    domain_to_conn: dict[str, int],
    all_conn_ids: list[int],
) -> list[int]:
    """Determine which connections an IP should be blocked on.

    Priority:
    1. Manual mapping (IP → explicit connection_ids)
    2. Automatic: target_host from CrowdSec meta → domain → connection_id
    3. Fallback: all connections
    """
    # 1. Manual mapping
    if ip_value in manual_mapping:
        return manual_mapping[ip_value]

    # 2. Automatic: resolve via target_host
    ip_hosts = target_hosts.get(ip_value, set())
    conn_ids: set[int] = set()
    for host in ip_hosts:
        conn_id = domain_to_conn.get(host)
        if conn_id is not None:
            conn_ids.add(conn_id)
    if conn_ids:
        return sorted(conn_ids)

    # 3. Fallback: all connections
    return all_conn_ids


def _sync_blocked_ips_conf() -> None:
    """Immediately sync ban decisions from CrowdSec to blocked_ips.conf
    (global + per-connection, with domain-aware routing) and reload Angie.
    """
    try:
        data = _run_cscli_json(["decisions", "list"])
        alerts = data if isinstance(data, list) else []

        # Collect all unique banned IPs
        ips: set[str] = set()
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            for dec in alert.get("decisions") or []:
                if not isinstance(dec, dict):
                    continue
                if dec.get("type") == "ban":
                    value = dec.get("value", "")
                    if value:
                        ips.add(value)

        header = (
            "# Auto-generated by WAF backend — do not edit manually\n"
            "# Updated on block/unblock actions and every 15s by blocked-ips-updater\n"
        )
        all_lines = [f"deny {ip};" for ip in sorted(ips)]
        global_content = header + "\n".join(all_lines) + "\n"

        # ── Global blocked_ips.conf (for default.conf) ──
        os.makedirs(os.path.dirname(BLOCKED_IPS_CONF), exist_ok=True)
        with open(BLOCKED_IPS_CONF, "w") as f:
            f.write(global_content)

        # ── Per-connection blocked_ips.conf (domain-aware) ──
        all_conn_ids = _load_connection_ids()
        manual_mapping = _load_blocked_ips_mapping()
        target_hosts = _extract_target_hosts_from_alerts(alerts)
        domain_to_conn = _build_domain_to_conn_map()

        # Build per-connection IP sets
        conn_ips: dict[int, set[str]] = {cid: set() for cid in all_conn_ids}
        for ip_val in ips:
            target_conns = _resolve_ip_connections(
                ip_val, manual_mapping, target_hosts, domain_to_conn, all_conn_ids
            )
            for cid in target_conns:
                conn_ips.setdefault(cid, set()).add(ip_val)

        for conn_id in all_conn_ids:
            conn_blocked_ips = os.path.join(
                CONNECTIONS_D_DIR, f"conn_{conn_id}", "blocked_ips.conf"
            )
            os.makedirs(os.path.dirname(conn_blocked_ips), exist_ok=True)
            cid_ips = conn_ips.get(conn_id, set())
            conn_lines = [f"deny {ip};" for ip in sorted(cid_ips)]
            conn_content = header + "\n".join(conn_lines) + "\n"
            with open(conn_blocked_ips, "w") as f:
                f.write(conn_content)

        # Reload Angie to apply changes
        client = docker.from_env()
        angie = client.containers.get(ANGIE_CONTAINER)
        angie.exec_run(["angie", "-s", "reload"])

        logger.info(
            "Synced %d blocked IPs to blocked_ips.conf (global + %d connections)",
            len(ips),
            len(all_conn_ids),
        )
    except Exception:
        logger.exception("Failed to sync blocked_ips.conf")


# ── Status ─────────────────────────────────────────────────


def get_status() -> CrowdSecStatus:
    """Get CrowdSec status."""
    try:
        _exit_code, stdout, _ = _run_cscli(["version"])
        version = ""
        for line in (stdout or "").splitlines():
            if "version" in line.lower():
                version = line.strip()
                break

        # Count decisions
        decisions_data = _run_cscli_json(["decisions", "list"])
        decisions_count = 0
        if isinstance(decisions_data, list):
            decisions_count = len(decisions_data)
        elif isinstance(decisions_data, dict):
            decisions_count = len(decisions_data.get("decisions", []) or [])

        # Count scenarios
        scenarios_data = _run_cscli_json(["scenarios", "list"])
        scenarios_count = 0
        if isinstance(scenarios_data, dict):
            scenarios_count = len(scenarios_data.get("scenarios", []) or [])
        elif isinstance(scenarios_data, list):
            scenarios_count = len(scenarios_data)

        # Count alerts
        alerts_data = _run_cscli_json(["alerts", "list"])
        alerts_count = 0
        if isinstance(alerts_data, list):
            alerts_count = len(alerts_data)
        elif isinstance(alerts_data, dict):
            alerts_count = len(alerts_data.get("alerts", []) or [])

        return CrowdSecStatus(
            running=True,
            version=version,
            decisions_count=decisions_count,
            scenarios_count=scenarios_count,
            alerts_count=alerts_count,
        )
    except Exception as e:
        logger.exception("Failed to get CrowdSec status")
        return CrowdSecStatus(running=False, version=str(e))


# ── Decisions ──────────────────────────────────────────────


def get_decisions() -> list[DecisionItem]:
    """Get all active decisions with per-connection blocking info."""
    data = _run_cscli_json(["decisions", "list"])
    # cscli decisions list -o json returns a list of alert objects:
    # [{"source": {"value": "ip"}, "decisions": [{"type": "ban", ...}]}]
    alerts = data if isinstance(data, list) else []
    if alerts is None:
        return []

    # Resolve connections for each IP
    all_conn_ids = _load_connection_ids()
    manual_mapping = _load_blocked_ips_mapping()
    target_hosts = _extract_target_hosts_from_alerts(alerts)
    domain_to_conn = _build_domain_to_conn_map()

    # Build connection_id → name lookup
    conn_id_to_name: dict[int, str] = {}
    for conn in _load_connections():
        cid = conn.get("id")
        if cid is not None:
            conn_id_to_name[cid] = conn.get("name", f"conn_{cid}")

    decisions = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        source = alert.get("source", {}) or {}
        ip_value = source.get("value", "") if isinstance(source, dict) else ""
        nested_decisions = alert.get("decisions", []) or []
        for dec in nested_decisions:
            if not isinstance(dec, dict):
                continue
            dec_value = dec.get("value", ip_value)
            # Determine which connections this IP is blocked on
            target_conn_ids = _resolve_ip_connections(
                dec_value, manual_mapping, target_hosts, domain_to_conn, all_conn_ids
            )
            blocked_on = [conn_id_to_name.get(cid, f"conn_{cid}") for cid in target_conn_ids]
            decisions.append(
                DecisionItem(
                    id=dec.get("id"),
                    source=dec.get("origin", "cscli"),
                    scope=dec.get("scope", "Ip"),
                    value=dec_value,
                    type=dec.get("type", "ban"),
                    reason=alert.get("scenario", ""),
                    duration=dec.get("duration", ""),
                    until=alert.get("stop_at", ""),
                    alert_id=alert.get("id"),
                    blocked_on=blocked_on,
                )
            )
    return decisions


def add_decision(req: DecisionCreate) -> dict:
    """Add a manual block decision, optionally scoped to specific connections."""
    args = ["decisions", "add"]
    args.extend(["--ip", req.ip])
    args.extend(["--duration", req.duration])
    args.extend(["--reason", req.reason])
    args.extend(["--type", req.type])
    exit_code, stdout, stderr = _run_cscli(args)

    # Log to ClickHouse for audit
    _log_manual_action("block", req.ip, req.duration, req.reason)

    if exit_code == 0:
        # Store per-IP connection mapping for manual blocks
        if req.connection_ids is not None:
            mapping = _load_blocked_ips_mapping()
            mapping[req.ip] = req.connection_ids
            _save_blocked_ips_mapping(mapping)
        else:
            # If no specific connections, remove any previous mapping
            # (so the IP becomes global — blocked on all connections)
            mapping = _load_blocked_ips_mapping()
            if req.ip in mapping:
                del mapping[req.ip]
                _save_blocked_ips_mapping(mapping)

        _sync_blocked_ips_conf()

    return {
        "success": exit_code == 0,
        "message": stdout.strip() if exit_code == 0 else stderr.strip(),
        "ip": req.ip,
        "action": "block",
    }


def delete_decision(ip: str) -> dict:
    """Remove a decision (unblock IP)."""
    exit_code, stdout, stderr = _run_cscli(["decisions", "delete", "--ip", ip])

    # Log to ClickHouse for audit
    _log_manual_action("unblock", ip, "", "manual unblock")

    if exit_code == 0:
        # Clean up the IP→connection mapping
        mapping = _load_blocked_ips_mapping()
        if ip in mapping:
            del mapping[ip]
            _save_blocked_ips_mapping(mapping)

        _sync_blocked_ips_conf()

    return {
        "success": exit_code == 0,
        "message": stdout.strip() if exit_code == 0 else stderr.strip(),
        "ip": ip,
        "action": "unblock",
    }


def delete_all_decisions() -> dict:
    """Remove all decisions and clear the IP→connection mapping."""
    exit_code, stdout, stderr = _run_cscli(["decisions", "delete", "--all"])

    if exit_code == 0:
        # Clear the entire IP→connection mapping
        if os.path.exists(BLOCKED_IPS_MAPPING):
            os.remove(BLOCKED_IPS_MAPPING)
        _sync_blocked_ips_conf()

    return {
        "success": exit_code == 0,
        "message": stdout.strip() if exit_code == 0 else stderr.strip(),
    }


# ── Scenarios ──────────────────────────────────────────────


def get_scenarios() -> list[ScenarioInfo]:
    """Get list of available scenarios and their status (active + disabled)."""
    data = _run_cscli_json(["scenarios", "list"])
    if not isinstance(data, dict | list):
        return []

    # cscli scenarios list -o json returns {"scenarios": [...]}
    items = data.get("scenarios", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []

    scenarios = []
    active_names: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        status = item.get("status", "")
        name = item.get("name", "")
        active_names.add(name)
        scenarios.append(
            ScenarioInfo(
                name=name,
                description=item.get("description", ""),
                loaded="enabled" in (status or ""),
                type=item.get("type", ""),
                labels=item.get("labels", []) if isinstance(item.get("labels"), list) else [],
            )
        )

    # Also find disabled scenarios (.yaml.disabled files) and include them
    try:
        container = _get_container()
        _exit_code, output = container.exec_run(
            ["sh", "-c", "ls /etc/crowdsec/scenarios/*.yaml.disabled 2>/dev/null || true"]
        )
        stdout = output.decode() if isinstance(output, bytes) else str(output)
        disabled_files = [f.strip() for f in stdout.splitlines() if f.strip()]
        if disabled_files:
            # Build name → metadata lookup from hub
            hub_items = get_scenario_hub_items()
            hub_meta: dict[str, dict] = {}
            for hi in hub_items:
                hub_meta[hi.get("name", "")] = hi

            for fpath in disabled_files:
                basename = fpath.rsplit("/", 1)[-1] if "/" in fpath else fpath
                # basename is e.g. "ssh-cve-2024-6387.yaml.disabled"
                stem = basename.replace(".yaml.disabled", "")
                # Try to find full name in hub metadata; fall back to stem
                full_name = ""
                meta = {}
                for candidate in (f"crowdsecurity/{stem}", stem):
                    if candidate in hub_meta:
                        full_name = candidate
                        meta = hub_meta[candidate]
                        break
                if not full_name:
                    full_name = stem

                # Skip if already in active list (shouldn't happen, but safe)
                if full_name in active_names:
                    continue

                scenarios.append(
                    ScenarioInfo(
                        name=full_name,
                        description=meta.get("description", ""),
                        loaded=False,
                        type=meta.get("type", "scenario"),
                        labels=meta.get("labels", [])
                        if isinstance(meta.get("labels"), list)
                        else [],
                    )
                )
    except Exception:
        logger.exception("Failed to list disabled scenarios")

    return scenarios


def get_scenario_hub_items() -> list[dict]:
    """Get list of available hub scenarios (both installed and not)."""
    # Get installed scenarios for quick lookup
    installed_data = _run_cscli_json(["scenarios", "list"])
    installed_names = set()
    if isinstance(installed_data, dict):
        for s in installed_data.get("scenarios", []) or []:
            if isinstance(s, dict):
                installed_names.add(s.get("name", ""))

    # List ALL available hub scenarios (including non-installed)
    data = _run_cscli_json(["hub", "list", "-a"])
    if not isinstance(data, dict):
        return []

    # cscli hub list -a -o json returns {"scenarios": [...], "parsers": [...], ...}
    scenario_list = data.get("scenarios", [])
    if not isinstance(scenario_list, list):
        return []

    items = []
    for item in scenario_list:
        if not isinstance(item, dict):
            continue
        item_name = item.get("name", "")
        status = item.get("status", "")
        installed = item_name in installed_names or "enabled" in status
        # Extract author from name (part before '/')
        author = item_name.split("/", 1)[0] if "/" in item_name else ""
        items.append(
            {
                "name": item_name,
                "description": item.get("description", ""),
                "author": author,
                "labels": item.get("labels", []) if isinstance(item.get("labels"), list) else [],
                "installed": installed,
                "path": item.get("local_path", ""),
            }
        )
    return items


def install_scenario(name: str) -> dict:
    """Install a scenario from the hub."""
    exit_code, stdout, stderr = _run_cscli(["scenarios", "install", name])
    return {
        "success": exit_code == 0,
        "message": stdout.strip() if exit_code == 0 else stderr.strip(),
    }


def remove_scenario(name: str) -> dict:
    """Remove a scenario and clean up any leftover files."""
    import re

    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_/\-.]*$", name):
        return {"success": False, "message": f"Invalid scenario name: {name}"}

    exit_code, stdout, stderr = _run_cscli(["scenarios", "remove", name])

    # Also physically delete any .yaml / .yaml.disabled remnants
    try:
        container = _get_container()
        basename = name.rsplit("/", 1)[-1] if "/" in name else name
        scenario_dir = "/etc/crowdsec/scenarios"
        yaml_path = f"{scenario_dir}/{basename}.yaml"
        disabled_path = f"{yaml_path}.disabled"
        container.exec_run(["sh", "-c", f"rm -f '{yaml_path}' '{disabled_path}'"])
    except Exception:
        logger.exception("Failed to clean up scenario files for %s", name)

    return {
        "success": exit_code == 0,
        "message": stdout.strip() if exit_code == 0 else stderr.strip(),
    }


def reload_crowdsec() -> dict:
    """Reload CrowdSec service."""
    exit_code, _stdout, stderr = _run_cscli(["hub", "update"])
    if exit_code != 0:
        return {"success": False, "message": f"Hub update failed: {stderr.strip()}"}

    exit_code, _stdout, stderr = _run_cscli(["hub", "upgrade"])
    if exit_code != 0:
        logger.warning("Hub upgrade warning: %s", stderr.strip())

    return {"success": True, "message": "CrowdSec reloaded (hub updated & upgraded)"}


# ── Service Toggle ─────────────────────────────────────────


def get_crowdsec_service_enabled() -> bool:
    """Check if CrowdSec is currently enabled (container running)."""
    try:
        client = docker.from_env()
        container = client.containers.get(CROWDSEC_CONTAINER)
        return container.status == "running"
    except Exception:
        return False


def toggle_crowdsec_service(enabled: bool) -> dict:
    """Enable or disable the CrowdSec service."""
    try:
        client = docker.from_env()
        container = client.containers.get(CROWDSEC_CONTAINER)

        if enabled:
            if container.status != "running":
                container.start()
                return {"success": True, "message": "CrowdSec service started", "enabled": True}
            return {
                "success": True,
                "message": "CrowdSec service is already running",
                "enabled": True,
            }
        else:
            if container.status == "running":
                container.stop()
                return {"success": True, "message": "CrowdSec service stopped", "enabled": False}
            return {
                "success": True,
                "message": "CrowdSec service is already stopped",
                "enabled": False,
            }
    except docker.errors.NotFound:
        return {
            "success": False,
            "message": f"CrowdSec container '{CROWDSEC_CONTAINER}' not found",
            "enabled": False,
        }
    except Exception as e:
        logger.exception("Failed to toggle CrowdSec service")
        return {"success": False, "message": str(e), "enabled": False}


# ── Scenario Toggle ────────────────────────────────────────


def toggle_scenario(name: str, enabled: bool) -> dict:
    """Enable or disable an individual CrowdSec scenario.

    Toggles by renaming the scenario .yaml file to .yaml.disabled (or vice
    versa) inside the CrowdSec container, then reloads via cscli hub upgrade.
    """
    return _toggle_scenario_by_file(name, enabled)


def _toggle_scenario_by_file(name: str, enabled: bool) -> dict:
    """Toggle scenario by renaming its YAML file (disable) or restoring it (enable).

    Scenario names from cscli include author prefixes (e.g.
    "crowdsecurity/ssh-time-based-bf"), but flat files at
    /etc/crowdsec/scenarios/ use only the basename (ssh-time-based-bf.yaml).
    """
    import re

    # Prevent shell injection — scenario names only contain these safe chars
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_/\-.]*$", name):
        return {
            "success": False,
            "message": f"Invalid scenario name: {name}",
            "name": name,
            "enabled": not enabled,
        }

    action = "enable" if enabled else "disable"
    try:
        container = _get_container()
        # Scenarios are stored flat in /etc/crowdsec/scenarios/
        # Name "crowdsecurity/ssh-time-based-bf" → basename "ssh-time-based-bf"
        scenario_dir = "/etc/crowdsec/scenarios"
        basename = name.rsplit("/", 1)[-1] if "/" in name else name

        yaml_path = f"{scenario_dir}/{basename}.yaml"
        disabled_path = f"{yaml_path}.disabled"

        if enabled:
            # Restore: rename .yaml.disabled -> .yaml
            script = (
                f"if [ -f '{disabled_path}' ]; then "
                f"mv '{disabled_path}' '{yaml_path}' && echo 'enabled'; "
                f"else echo 'not_found'; fi"
            )
        else:
            # Disable: rename .yaml -> .yaml.disabled
            script = (
                f"if [ -f '{yaml_path}' ]; then "
                f"mv '{yaml_path}' '{disabled_path}' && echo 'disabled'; "
                f"else echo 'not_found'; fi"
            )

        _exit_code, output = container.exec_run(["sh", "-c", script])
        stdout = output.decode() if isinstance(output, bytes) else str(output)
        stdout = stdout.strip()

        if "not_found" in stdout:
            return {
                "success": False,
                "message": f"Scenario file not found: {basename}.yaml",
                "name": name,
                "enabled": not enabled,
            }

        # Reload CrowdSec to apply changes
        container.exec_run(["cscli", "hub", "upgrade"])

        return {
            "success": True,
            "message": f"Scenario {action}d successfully (file toggle)",
            "name": name,
            "enabled": enabled,
        }
    except Exception as e:
        logger.exception("Failed to toggle scenario via file")
        return {
            "success": False,
            "message": f"Failed to {action} scenario: {e}",
            "name": name,
            "enabled": not enabled,
        }


# ── Audit log ──────────────────────────────────────────────


def _log_manual_action(action: str, ip: str, duration: str, reason: str) -> None:
    """Log manual block/unblock action to ClickHouse for audit."""
    if _ch_client is None:
        return
    try:
        import datetime as dt

        _ch_client.execute(
            """
            INSERT INTO logs.crowdsec_manual_blocks
            (timestamp, action, ip, duration, reason, source)
            VALUES
        """,
            [(dt.datetime.utcnow(), action, ip, duration, reason, "waf-panel")],
        )
    except Exception:
        logger.exception("Failed to log manual action to ClickHouse")


def get_manual_block_log(limit: int = 100, hours: float | None = None) -> list:
    """Get manual block audit log from ClickHouse.

    Args:
        limit: Maximum number of rows to return.
        hours: Optional time window in hours. When supplied, restricts to
            entries newer than ``now() - INTERVAL N MINUTE``. ``None`` means
            no time filter (legacy behaviour).
    """
    if _ch_client is None:
        return []
    try:
        if hours is not None and hours > 0:
            minutes = max(1, int(min(max(hours, 0.0167), 8760) * 60))
            query = (
                "SELECT timestamp, action, ip, duration, reason, source "
                "FROM logs.crowdsec_manual_blocks "
                f"WHERE timestamp >= now() - INTERVAL {minutes} MINUTE "
                "ORDER BY timestamp DESC LIMIT %(limit)s"
            )
        else:
            query = (
                "SELECT timestamp, action, ip, duration, reason, source "
                "FROM logs.crowdsec_manual_blocks "
                "ORDER BY timestamp DESC LIMIT %(limit)s"
            )
        rows = _ch_client.execute(query, {"limit": limit})
        return [
            {
                "timestamp": row[0].isoformat() if row[0] else None,
                "action": row[1],
                "ip": row[2],
                "duration": row[3],
                "reason": row[4],
                "source": row[5],
            }
            for row in rows
        ]
    except Exception:
        logger.exception("Failed to read manual block log")
        return []


# ── Alerts ─────────────────────────────────────────────────


def get_alerts(hours: float | None = None) -> list[AlertItem]:
    """Get list of alerts from CrowdSec.

    Args:
        hours: Optional time window in hours. Filtering is applied
            client-side against ``start_at`` because ``cscli`` does not
            expose a uniform time-window flag across versions.
    """
    data = _run_cscli_json(["alerts", "list"])
    if not isinstance(data, list):
        return []

    cutoff: datetime | None = None
    if hours is not None and hours > 0:
        try:
            cutoff = datetime.now(UTC) - timedelta(
                minutes=max(1, int(min(max(hours, 0.0167), 8760) * 60))
            )
        except Exception:
            cutoff = None

    alerts = []
    for item in data:
        if not isinstance(item, dict):
            continue
        source = item.get("source", {}) or {}
        start_at = item.get("start_at", "")
        if cutoff is not None and start_at:
            parsed = _parse_alert_timestamp(start_at)
            if parsed is not None and parsed < cutoff:
                continue
        alerts.append(
            AlertItem(
                id=item.get("id"),
                scenario=item.get("scenario", ""),
                message=item.get("message", ""),
                source_ip=source.get("value", "") if isinstance(source, dict) else "",
                source_scope=source.get("scope", "Ip") if isinstance(source, dict) else "Ip",
                start_at=start_at,
                stop_at=item.get("stop_at", ""),
                capacity=item.get("capacity"),
                decisions_count=len(item.get("decisions", []) or []),
            )
        )
    return alerts


def _parse_alert_timestamp(value: str) -> datetime | None:
    """Best-effort parsing of CrowdSec alert timestamps.

    cscli emits a mix of formats across versions
    (``2026-05-19T12:34:56Z``, with/without microseconds, with a timezone
    offset). Returning ``None`` on failure means "don't filter out".
    """
    if not value:
        return None
    # Trim sub-second precision past microseconds (Python <3.11 chokes on >6 digits).
    normalised = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalised)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None
