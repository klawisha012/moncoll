# --- Этап 1: Подготовка Core Rule Set (CRS) ---
FROM alpine:3.19 AS crs
RUN apk add --no-cache git \
    && git clone -b v3.3.5 https://github.com/coreruleset/coreruleset /crs \
    && cp /crs/crs-setup.conf.example /crs/crs-setup.conf \
    && cp /crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf \
    && cp /crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example /crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

# --- Этап 2: Основной образ ---
FROM docker.angie.software/angie:latest

# Устанавливаем только существующие пакеты модулей
# ВНИМАНИЕ: ACME уже встроен в 'angie', его ставить не нужно.
RUN apk add --no-cache \
    angie-module-modsecurity \
    angie-module-geoip2 \
    angie-module-echo \
    angie-module-zip \
    angie-module-zstd \
    angie-module-lua \
    curl tar lua5.1 lua5.1-cjson lua5.1-socket gettext git

COPY --from=crs /crs /var/lib/angie/modsecurity/coreruleset

# Установка CrowdSec Bouncer
RUN curl -L -o /tmp/bouncer.tgz "https://github.com/crowdsecurity/cs-nginx-bouncer/releases/download/v1.1.5/crowdsec-nginx-bouncer.tgz" \
    && mkdir -p /tmp/bouncer-extract /usr/local/lua/crowdsec \
    && tar xzf /tmp/bouncer.tgz -C /tmp/bouncer-extract --strip-components=1 \
    && (cd /tmp/bouncer-extract && find . -type f -name "*.lua" | while read -r f; do \
         mkdir -p "/usr/local/lua/crowdsec/$(dirname "$f")"; \
         cp "$f" "/usr/local/lua/crowdsec/$f"; \
       done) \
    && mkdir -p /etc/crowdsec/bouncers/ \
    && find /tmp/bouncer-extract -type f -name "*bouncer*.conf" | head -1 | xargs -I{} cp {} /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf \
    && rm -rf /tmp/bouncer.tgz /tmp/bouncer-extract

# Активируем динамические модули (acme здесь НЕ нужен, он встроен)
ENV ANGIE_LOAD_MODULES="modsecurity,geoip2,echo,zip,zstd,ndk,lua"

# Конфигурация Lua для CrowdSec
RUN mkdir -p /etc/angie/http.d/ \
    && printf 'lua_package_path "/usr/local/lua/crowdsec/?.lua;/usr/local/lua/crowdsec/?/init.lua;;";\n' > /etc/angie/http.d/crowdsec.conf \
    && printf 'lua_shared_dict crowdsec_cache 50m;\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf 'init_by_lua_block {\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '    local cs = require "crowdsec"\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '    local ok, err = cs.init("/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf", "crowdsec-angie-bouncer/v1.0")\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '    if not ok then\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '        ngx.log(ngx.ERR, "[CrowdSec] Error: " .. (err or "unknown"))\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '    end\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '}\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf 'access_by_lua_block {\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '    local cs = require "crowdsec"\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '    cs.allow_request()\n' >> /etc/angie/http.d/crowdsec.conf \
    && printf '}\n' >> /etc/angie/http.d/crowdsec.conf

RUN printf '#!/bin/sh\ncscli bouncers add angie-bouncer\n' > /usr/local/bin/register-bouncer.sh \
    && chmod +x /usr/local/bin/register-bouncer.sh