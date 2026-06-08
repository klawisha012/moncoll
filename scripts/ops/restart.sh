#!/bin/sh

set -e

auto_confirm=0

confirm () {
    if [ "$auto_confirm" = "1" ]; then
        return 0
    fi

    printf "Are you sure you want to proceed? (y/N) "
    read -r REPLY
    case "$REPLY" in
        [Yy])
            ;;
        *)
            echo "Script canceled."
            exit 1
            ;;
    esac
}

if [ "$1" = "-y" ]; then
    auto_confirm=1
fi

echo ""
echo "*** This will restart all WAF containers ***"
echo ""

confirm

COMPOSE_FILES="-f docker-compose.yaml"
if [ -f "./dev/docker-compose.dev.yml" ]; then
    COMPOSE_FILES="$COMPOSE_FILES -f ./dev/docker-compose.dev.yml"
fi

if [ -f ".env" ]; then
    docker compose $COMPOSE_FILES down --remove-orphans
    docker compose $COMPOSE_FILES up -d
elif [ -f ".env.example" ]; then
    echo "No .env found, using .env.example for docker compose..."
    docker compose --env-file .env.example $COMPOSE_FILES down --remove-orphans
    docker compose --env-file .env.example $COMPOSE_FILES up -d
else
    echo "No .env or .env.example found, can't restart containers."
    exit 1
fi

echo ""
echo "===> Container status:"
docker compose $COMPOSE_FILES ps
echo ""
echo "Restart complete!"
echo ""
