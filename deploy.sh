#!/usr/bin/env bash
set -euo pipefail

STACK_NAME="waf"
REGISTRY="${REGISTRY:-localhost:5000}"
COMPOSE_FILE="docker-compose.swarm.yml"
IMAGE_TAG="3.3.5"

echo "=== WAF Stack Deployment ==="

# Check if Docker Swarm is initialized
if ! docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null | grep -q "active"; then
    echo "[!] Docker Swarm is not initialized."
    echo "    Run: docker swarm init"
    exit 1
fi

# Create env files from examples if they don't exist
for env_file in angie clickhouse vector; do
    if [ ! -f "./envs/${env_file}.env" ] && [ -f "./envs/${env_file}-example.env" ]; then
        echo "[*] Creating envs/${env_file}.env from example"
        cp "./envs/${env_file}-example.env" "./envs/${env_file}.env"
    fi
done

# Build angie image
echo "[*] Building angie-modsec-crs:${IMAGE_TAG}..."
docker build -t "${REGISTRY}/angie-modsec-crs:${IMAGE_TAG}" -f angie.Dockerfile .

# Push to registry if not local
if [ "${REGISTRY}" != "localhost:5000" ]; then
    echo "[*] Pushing image to ${REGISTRY}..."
    docker push "${REGISTRY}/angie-modsec-crs:${IMAGE_TAG}"
fi

# Deploy the stack
echo "[*] Deploying stack '${STACK_NAME}'..."
REGISTRY="${REGISTRY}" docker stack deploy -c "${COMPOSE_FILE}" "${STACK_NAME}"

echo ""
echo "=== Stack '${STACK_NAME}' deployed ==="
echo ""
echo "Services:"
docker stack services "${STACK_NAME}"
echo ""
echo "Check status:  docker stack ps ${STACK_NAME}"
echo "Check logs:    docker service logs ${STACK_NAME}_angie"
echo "Remove stack:  docker stack rm ${STACK_NAME}"
echo ""
echo "Endpoints:"
echo "  WAF/Angie:  http://<node-ip>:80"
echo "  Grafana:    http://<node-ip>:3000"
echo "  ClickHouse: http://<node-ip>:8123"
