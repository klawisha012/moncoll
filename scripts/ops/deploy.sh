#!/usr/bin/env bash
set -euo pipefail

STACK_NAME="waf"
REGISTRY="${REGISTRY:-localhost:5000}"
COMPOSE_FILE="containers/docker/docker-compose.swarm.yaml"
IMAGE_TAG="3.3.5"

# Цвета для вывода
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

echo "=== WAF Stack Deployment ==="

# --- 1. Проверка Docker Swarm ---
if ! docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
    error "Docker Swarm не инициализирован. Запустите: docker swarm init"
fi
NODE_ID=$(docker info --format '{{.Swarm.NodeID}}')
info "Swarm активен. Node ID: ${NODE_ID}"

# --- 2. Создание env-файлов из .env ---
if [ ! -f ".env" ]; then
    error "Файл .env не найден. Запустите: bash scripts/setup/generate-env.sh"
fi
mkdir -p envs
grep '^ANGIE_'      .env > envs/angie.env
{ grep '^VECTOR_' .env; grep '^CLICKHOUSE_' .env; } > envs/vector.env
grep '^CLICKHOUSE_' .env > envs/clickhouse.env
info "env-файлы созданы из .env"

# --- 3. Создание Docker Secrets (если не существуют) ---
create_secret() {
    local name="$1"
    local prompt="$2"
    if ! docker secret inspect "${name}" &>/dev/null; then
        warn "Secret '${name}' не найден."
        read -r -s -p "  Введите ${prompt}: " secret_val
        echo
        printf '%s' "${secret_val}" | docker secret create "${name}" -
        info "Secret '${name}' создан"
    else
        info "Secret '${name}' уже существует, пропускаем"
    fi
}
create_secret "clickhouse_password" "пароль ClickHouse"

# --- 4. Навешиваем labels на текущую ноду (для ClickHouse) ---
info "Устанавливаю node labels для stateful-сервисов..."
docker node update --label-add clickhouse=true "${NODE_ID}" 2>/dev/null || true

# --- 5. Создание Docker Configs ---
create_or_update_config() {
    local name="$1"
    local file="$2"
    if [ ! -f "${file}" ]; then
        warn "Файл ${file} не найден, пропускаю config '${name}'"
        return
    fi
    # Удаляем старую версию если есть (нельзя обновить config in-place в Swarm)
    if docker config inspect "${name}" &>/dev/null; then
        warn "Config '${name}' уже существует. Для обновления удалите его вручную:"
        warn "  docker config rm ${name} && ./scripts/ops/deploy.sh"
    else
        docker config create "${name}" "${file}"
        info "Config '${name}' создан из ${file}"
    fi
}

create_or_update_config "angie_conf"        "./configs/angie/angie.conf"
create_or_update_config "angie_default"     "./configs/angie/http.d/_default.conf"
create_or_update_config "modsecurity_conf"  "./configs/angie/modsecurity/modsecurity.conf"
create_or_update_config "modsecurity_rules" "./configs/angie/modsecurity/rules.conf"
create_or_update_config "vector_yaml"       "./configs/vector/vector.yaml"

# Пока что заглушка для crowdsec, поскольку не настроен.
echo "# crowdsec disabled" > /tmp/crowdsec_empty.conf
create_or_update_config "crowdsec_conf"     "/tmp/crowdsec_empty.conf"

# --- 6. Сборка образа Angie ---
info "Сборка angie-modsec-crs:${IMAGE_TAG}..."
docker build -t "${REGISTRY}/angie-modsec-crs:${IMAGE_TAG}" -f ./configs/angie/Dockerfile .

# Push если реестр не локальный
if [ "${REGISTRY}" != "localhost:5000" ]; then
    info "Пушим образ в ${REGISTRY}..."
    docker push "${REGISTRY}/angie-modsec-crs:${IMAGE_TAG}"
fi

# --- 7. Деплой стека ---
info "Деплоим стек '${STACK_NAME}'..."
REGISTRY="${REGISTRY}" docker stack deploy \
    --compose-file "${COMPOSE_FILE}" \
    --with-registry-auth \
    --prune \
    "${STACK_NAME}"

# Заплатка против datetime64 в init.sql --- 9. Создание таблиц в ClickHouse ---
info "Ожидаю запуска ClickHouse..."
sleep 20
CLICKHOUSE_USER=$(grep '^CLICKHOUSE_USER=' .env | cut -d'=' -f2)
CLICKHOUSE_PASSWORD=$(grep '^CLICKHOUSE_PASSWORD=' .env | cut -d'=' -f2)

sed 's/TTL timestamp + INTERVAL/TTL toDateTime(timestamp) + INTERVAL/g;
     s/TTL time_local + INTERVAL/TTL toDateTime(time_local) + INTERVAL/g' \
  configs/clickhouse/init.sql | \
  docker exec -i $(docker ps -q -f name=waf_clickhouse) \
    clickhouse-client \
    --user "$CLICKHOUSE_USER" \
    --password "$CLICKHOUSE_PASSWORD" \
    --multiline --multiquery 2>&1 | grep -v jemalloc || true

info "Таблицы ClickHouse созданы"

echo ""
echo "=== Стек '${STACK_NAME}' задеплоен ==="
echo ""
echo "Сервисы:"
docker stack services "${STACK_NAME}"
echo ""
echo "Полезные команды:"
echo "  Статус задач:    docker stack ps ${STACK_NAME}"
echo "  Логи Angie:      docker service logs -f ${STACK_NAME}_angie"
echo "  Логи Vector:     docker service logs -f ${STACK_NAME}_vector"
echo "  Логи ClickHouse: docker service logs -f ${STACK_NAME}_clickhouse"
echo "  Удалить стек:    docker stack rm ${STACK_NAME}"
echo ""
echo "Эндпоинты:"
echo "  WAF/Angie:  http://<node-ip>:80"
echo "  ClickHouse: http://<node-ip>:8123"
