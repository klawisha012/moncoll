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

    m = re.search(r"keepalive_timeout\s+(\d+);", content, re.MULTILINE)
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

    log_format = (
        "    log_format with_geoip_json escape=json '{'\n"
        '        \'"time_local":"$time_local",\'\n'
        '        \'"remote_addr":"$remote_addr",\'\n'
        '        \'"x_forwarded_for":"$http_x_forwarded_for",\'\n'
        '        \'"remote_user":"$remote_user",\'\n'
        '        \'"request_method":"$request_method",\'\n'
        '        \'"request_uri":"$request_uri",\'\n'
        '        \'"server_protocol":"$server_protocol",\'\n'
        '        \'"status": "$status",\'\n'
        '        \'"body_bytes_sent":"$body_bytes_sent",\'\n'
        '        \'"http_referer":"$http_referer",\'\n'
        '        \'"http_user_agent":"$http_user_agent",\'\n'
        "        '\"geoip\":{'\n"
        '            \'"country_name":"$geoip2_data_country_name",\'\n'
        '            \'"country_code":"$geoip2_data_country_code",\'\n'
        '            \'"city_name":"$geoip2_data_city_name",\'\n'
        '            \'"postal_code":"$geoip2_data_postal_code",\'\n'
        '            \'"latitude":"$geoip2_data_latitude",\'\n'
        '            \'"longitude":"$geoip2_data_longitude",\'\n'
        '            \'"asn":"$geoip2_data_asn",\'\n'
        '            \'"organization":"$geoip2_data_organization"\'\n'
        "        '}'\n"
        "    '}';"
    )

    return f"""{modules_block}

user  angie;
worker_processes  {settings.worker_processes};
worker_rlimit_nofile {settings.worker_rlimit_nofile};

pid        /run/angie/angie.pid;

events {{
    worker_connections  {settings.worker_connections};
}}


http {{
    # Real IP from X-Forwarded-For (Docker / reverse proxy)
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    geoip2 /etc/angie/geoip2/GeoLite2-Country.mmdb {{
        auto_reload 1h;
        $geoip2_data_country_code source=$http_x_forwarded_for country iso_code;
        $geoip2_data_country_name source=$http_x_forwarded_for country names ru;
    }}

    geoip2 /etc/angie/geoip2/GeoLite2-ASN.mmdb {{
        auto_reload 1h;
        $geoip2_data_asn source=$http_x_forwarded_for autonomous_system_number;
        $geoip2_data_organization source=$http_x_forwarded_for autonomous_system_organization;
    }}

    geoip2 /etc/angie/geoip2/GeoLite2-City.mmdb {{
        auto_reload 1h;
        $geoip2_data_city_name source=$http_x_forwarded_for city names ru;
        $geoip2_data_postal_code source=$http_x_forwarded_for postal code;
        $geoip2_data_latitude source=$http_x_forwarded_for location latitude;
        $geoip2_data_longitude source=$http_x_forwarded_for location longitude;
    }}

    include       /etc/angie/mime.types;
    default_type  application/octet-stream;

{log_format}

    map $geoip2_data_country_code $denied {{
{denied_block}
    }}

    {sendfile_line}

    keepalive_timeout  {settings.keepalive_timeout};

    ## Dynamic connection configs + static server configs (generated by WAF backend)
    include /etc/angie/http.d/*.conf;
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
