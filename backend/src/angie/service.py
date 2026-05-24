import re
from pathlib import Path

from .schemas import AngieSettings, ModuleInfo

ANGIE_CONFIG_DIR = Path("/app/etc/angie")
ANGIE_CONFIG_FILE = ANGIE_CONFIG_DIR / "angie.conf"

ALL_MODULES = [
    "ngx_http_auth_jwt_module.so",
    "ngx_http_auth_ldap_module.so",
    "ngx_http_auth_pam_module.so",
    "ngx_http_auth_spnego_module.so",
    "ngx_http_auth_totp_module.so",
    "ngx_http_brotli_filter_module.so",
    "ngx_http_brotli_static_module.so",
    "ngx_http_cache_purge_module.so",
    "ngx_http_cgi_module.so",
    "ngx_http_combined_upstreams_module.so",
    "ngx_http_dav_ext_module.so",
    "ngx_http_dynamic_limit_req_module.so",
    "ngx_http_echo_module.so",
    "ngx_http_enhanced_memcached_module.so",
    "ngx_http_eval_module.so",
    "ngx_http_geoip2_module.so",
    "ngx_stream_geoip2_module.so",
    "ngx_http_headers_more_filter_module.so",
    "ngx_http_auth_radius_module.so",
    "ngx_http_image_filter_module.so",
    "ngx_http_keyval_module.so",
    "ngx_stream_keyval_module.so",
    "ndk_http_module.so",
    "ngx_http_lua_module.so",
    "ngx_stream_lua_module.so",
    "ngx_http_modsecurity_module.so",
    "ngx_http_js_module.so",
    "ngx_stream_js_module.so",
    "ngx_http_opentracing_module.so",
    "ngx_otel_module.so",
    "ngx_http_perl_module.so",
    "ngx_postgres_module.so",
    "ngx_http_redis2_module.so",
    "ngx_rtmp_module.so",
    "ngx_http_set_misc_module.so",
    "ngx_http_subs_filter_module.so",
    "ngx_http_testcookie_access_module.so",
    "ngx_http_unbrotli_filter_module.so",
    "ngx_http_upload_module.so",
    "ngx_http_vod_module.so",
    "ngx_http_stream_server_traffic_status_module.so",
    "ngx_http_vhost_traffic_status_module.so",
    "ngx_stream_server_traffic_status_module.so",
    "ngx_wasm_module.so",
    "ngx_wasm_core_module.so",
    "ngx_http_wasm_host_module.so",
    "ngx_wasmtime_module.so",
    "ngx_http_xslt_filter_module.so",
    "ngx_http_zip_module.so",
    "ngx_http_zstd_filter_module.so",
    "ngx_http_zstd_static_module.so",
]


def parse_angie_config(content: str) -> AngieSettings:
    settings = AngieSettings()

    m = re.search(r"^worker_processes\s+(\S+);", content, re.MULTILINE)
    if m:
        settings.worker_processes = m.group(1)

    m = re.search(r"^worker_rlimit_nofile\s+(\d+);", content, re.MULTILINE)
    if m:
        settings.worker_rlimit_nofile = int(m.group(1))

    m = re.search(r"worker_connections\s+(\d+);", content, re.MULTILINE)
    if m:
        settings.worker_connections = int(m.group(1))

    m = re.search(r"keepalive_timeout\s+(\d+)s?;", content, re.MULTILINE)
    if m:
        settings.keepalive_timeout = int(m.group(1))

    settings.sendfile = "sendfile        on;" in content

    m = re.search(r"map\s+\$geoip2_data_country_code\s+\$denied\s*\{([^}]+)\}", content, re.DOTALL)
    if m:
        countries = re.findall(r'^\s+(\w+)\s+"1"', m.group(1), re.MULTILINE)
        settings.denied_countries = countries

    loaded_modules = set(re.findall(r"^load_module\s+modules/(\S+\.so);", content, re.MULTILINE))
    modules = []
    for mod_name in ALL_MODULES:
        modules.append(ModuleInfo(name=mod_name, loaded=mod_name in loaded_modules))
    settings.modules = modules

    return settings


def generate_angie_config(settings: AngieSettings) -> str:
    module_lines = []
    for mod in settings.modules:
        if mod.loaded:
            module_lines.append(f"load_module modules/{mod.name};")

    modules_block = "\n".join(module_lines)

    denied_block = "\n".join(f'        {code} "1";' for code in settings.denied_countries)

    sendfile_line = "sendfile        on;" if settings.sendfile else "sendfile        off;"

    return f"""{modules_block}
# ACME module is built into Angie - no need to load it separately

user  angie;
# Max-RPS tuning: one worker per core, raise FD ceiling well above worker_connections.
worker_processes  {settings.worker_processes};
worker_rlimit_nofile {settings.worker_rlimit_nofile};

# Pin workers to CPUs for cache locality (no-op when only 1 CPU).
worker_cpu_affinity auto;

pid        /run/angie/angie.pid;

events {{
    worker_connections  {settings.worker_connections};
    multi_accept on;
    use epoll;
    accept_mutex off;
}}


http {{
    # Real IP from X-Forwarded-For (Docker / reverse proxy)
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 127.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    geoip2 /etc/angie/geoip2/GeoLite2-Country.mmdb {{
        auto_reload 1h;
        $geoip2_data_country_code source=$remote_addr country iso_code;
        $geoip2_data_country_name source=$remote_addr country names ru;
    }}

    geoip2 /etc/angie/geoip2/GeoLite2-ASN.mmdb {{
        auto_reload 1h;
        $geoip2_data_asn source=$remote_addr autonomous_system_number;
        $geoip2_data_organization source=$remote_addr autonomous_system_organization;
    }}

    geoip2 /etc/angie/geoip2/GeoLite2-City.mmdb {{
        auto_reload 1h;
        $geoip2_data_city_name source=$remote_addr city names ru;
        $geoip2_data_postal_code source=$remote_addr postal code;
        $geoip2_data_latitude source=$remote_addr location latitude;
        $geoip2_data_longitude source=$remote_addr location longitude;
    }}

    include       /etc/angie/mime.types;
    default_type  application/octet-stream;

    # ────────────────────────────────────────────────────────────
    # ModSecurity (global) — rules loaded ONCE at http scope so every
    # server (default fallback + dynamic conn_*) inherits WAF
    # protection. Per-location `modsecurity off;` still overrides
    # (e.g. ACME challenge, websocket upgrade endpoints).
    #
    # IMPORTANT: do NOT add `modsecurity_rules_file` at server scope —
    # ModSecurity-nginx loads rules at every scope they're declared,
    # producing duplicate-ID rule sets that silently kill workers
    # (empty replies, no error logged).
    # ────────────────────────────────────────────────────────────
    modsecurity on;
    modsecurity_rules_file /etc/angie/modsecurity/rules.conf;

    log_format with_geoip_json escape=json '{{'
        '"time_local":"$time_local",'
        '"remote_addr":"$remote_addr",'
        '"x_forwarded_for":"$http_x_forwarded_for",'
        '"remote_user":"$remote_user",'
        '"request_method":"$request_method",'
        '"request_uri":"$request_uri",'
        '"server_protocol":"$server_protocol",'
        '"status": "$status",'
        '"body_bytes_sent":"$body_bytes_sent",'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent",'
        '"host":"$host",'
        '"geoip":{{'
            '"country_name":"$geoip2_data_country_name",'
            '"country_code":"$geoip2_data_country_code",'
            '"city_name":"$geoip2_data_city_name",'
            '"postal_code":"$geoip2_data_postal_code",'
            '"latitude":"$geoip2_data_latitude",'
            '"longitude":"$geoip2_data_longitude",'
            '"asn":"$geoip2_data_asn",'
            '"organization":"$geoip2_data_organization"'
        '}}'
    '}}';

    map $geoip2_data_country_code $denied {{
{denied_block}
    }}

    # ────────────────────────────────────────────────────────────
    # Max-RPS: networking + filesystem fast paths
    # ────────────────────────────────────────────────────────────
    {sendfile_line}
    tcp_nopush      on;
    tcp_nodelay     on;

    # Keep client connections alive much longer so HTTP/1.1 clients don't
    # pay the handshake cost on every request. 10k requests per connection
    # is well past the point where the connection itself is the bottleneck.
    keepalive_timeout  {settings.keepalive_timeout}s;
    keepalive_requests 10000;

    # Hide version + cut a couple of redundant headers.
    server_tokens off;

    # File-descriptor cache for static files.
    open_file_cache          max=200000 inactive=60s;
    open_file_cache_valid    30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors   on;

    # Larger hash tables so server_name/MIME lookups don't degrade with many domains.
    server_names_hash_bucket_size 128;
    server_names_hash_max_size    8192;
    types_hash_max_size 4096;
    variables_hash_max_size 2048;

    # Request buffers — bigger by default so we don't spill to disk on normal traffic.
    client_body_buffer_size      128k;
    client_header_buffer_size    4k;
    large_client_header_buffers  8 16k;
    client_max_body_size         32m;
    client_body_timeout          30s;
    client_header_timeout        30s;
    send_timeout                 30s;
    reset_timedout_connection    on;

    # Upstream pool: keep idle connections to backends so we skip TCP/TLS setup
    # on every proxy_pass. Per-server upstreams set their own `keepalive N`.
    proxy_http_version 1.1;
    proxy_set_header   Connection "";

    # WebSocket upgrade map: when a client sends `Upgrade: websocket`,
    # `$connection_upgrade` becomes "upgrade"; on plain HTTP it stays empty
    # so upstream keepalive (Connection: "") still works. Used by every
    # generated proxy location so Socket.IO / SSE / raw WS just work.
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        ''      '';
    }}

    # ────────────────────────────────────────────────────────────
    # HTTP/2 tuning
    # ────────────────────────────────────────────────────────────
    http2_max_concurrent_streams 256;
    http2_recv_buffer_size       256k;

    # ────────────────────────────────────────────────────────────
    # HTTP/3 (QUIC) — enabled per server block via `listen 443 quic`.
    # These globals tune the QUIC stack.
    # ────────────────────────────────────────────────────────────
    quic_retry on;
    quic_gso   on;
    ssl_early_data on;

    # ────────────────────────────────────────────────────────────
    # Dynamic compression — Angie / nginx negotiates per request via the
    # client's Accept-Encoding header. Order of preference is decided by
    # the client; if multiple modules can serve a response, the first
    # encoding in Accept-Encoding wins. We enable zstd → brotli → gzip.
    # ────────────────────────────────────────────────────────────
    map $http_accept_encoding $waf_pref_encoding {{
        default          "gzip";
        "~*\\bzstd\\b"     "zstd";
        "~*\\bbr\\b"       "brotli";
        "~*\\bgzip\\b"     "gzip";
    }}

    # MIME types worth compressing (text-shaped payloads).
    map $sent_http_content_type $waf_compressible {{
        default                                 0;
        "~*^text/"                              1;
        "~*application/javascript"              1;
        "~*application/x-javascript"            1;
        "~*application/json"                    1;
        "~*application/ld\\+json"                1;
        "~*application/xml"                     1;
        "~*application/xhtml\\+xml"              1;
        "~*application/rss\\+xml"                1;
        "~*application/atom\\+xml"               1;
        "~*application/vnd\\.ms-fontobject"      1;
        "~*application/wasm"                    1;
        "~*font/"                               1;
        "~*image/svg\\+xml"                      1;
    }}

    # ── gzip (RFC 1952) ──
    gzip               on;
    gzip_vary          on;
    gzip_proxied       any;
    gzip_comp_level    5;
    gzip_min_length    256;
    gzip_http_version  1.1;
    gzip_types
        text/plain text/css text/xml text/javascript
        application/javascript application/x-javascript
        application/json application/ld+json
        application/xml application/xhtml+xml
        application/rss+xml application/atom+xml
        application/vnd.ms-fontobject application/wasm
        font/ttf font/otf font/eot
        image/svg+xml;
    gzip_disable "msie6";

    # ── brotli (RFC 7932) ──
    brotli              on;
    brotli_static       on;
    brotli_comp_level   5;
    brotli_min_length   256;
    brotli_types
        text/plain text/css text/xml text/javascript
        application/javascript application/x-javascript
        application/json application/ld+json
        application/xml application/xhtml+xml
        application/rss+xml application/atom+xml
        application/vnd.ms-fontobject application/wasm
        font/ttf font/otf font/eot
        image/svg+xml;

    # ── zstd (RFC 8478) ──
    zstd                on;
    zstd_static         on;
    zstd_comp_level     3;
    zstd_min_length     256;
    zstd_types
        text/plain text/css text/xml text/javascript
        application/javascript application/x-javascript
        application/json application/ld+json
        application/xml application/xhtml+xml
        application/rss+xml application/atom+xml
        application/vnd.ms-fontobject application/wasm
        font/ttf font/otf font/eot
        image/svg+xml;

    # Docker DNS resolver
    resolver 127.0.0.11 valid=30s ipv6=off;

    ## Static server configs (default.conf, crowdsec.conf, etc.)
    include /etc/angie/http.d/*.conf;

    ## Dynamic connection configs — per-tenant isolation (Phase 13).
    ## Each active tenant has /etc/angie/tenants/<id>/compose/conn_*/<id>.conf
    ## Suspended tenants have their compose/ renamed to compose.suspended/ so
    ## this glob stops matching them automatically.
    include /etc/angie/tenants/*/compose/conn_*/*.conf;
}}
"""


def get_angie_settings() -> AngieSettings:
    if ANGIE_CONFIG_FILE.exists():
        content = ANGIE_CONFIG_FILE.read_text()
        return parse_angie_config(content)
    return AngieSettings()


def save_angie_settings(settings: AngieSettings) -> Path:
    ANGIE_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    content = generate_angie_config(settings)
    ANGIE_CONFIG_FILE.write_text(content)
    return ANGIE_CONFIG_FILE
