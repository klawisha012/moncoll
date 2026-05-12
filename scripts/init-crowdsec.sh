#!/bin/bash
# Script to initialize CrowdSec and register the bouncer

set -e

echo "Initializing CrowdSec..."

# Wait for CrowdSec to be ready
until docker exec crowdsec cscli version > /dev/null 2>&1; do
  echo "Waiting for CrowdSec to start..."
  sleep 2
done

# Register the angie bouncer (matches the name in crowdsec.conf init_by_lua_block)
echo "Registering angie bouncer..."
API_KEY=$(docker exec crowdsec cscli bouncers add angie-bouncer -o raw)

# Update .env file with the API key
if grep -q "CROWDSEC_BOUNCER_KEY" .env; then
  sed -i "s/CROWDSEC_BOUNCER_KEY=.*/CROWDSEC_BOUNCER_KEY=$API_KEY/" .env
else
  echo "CROWDSEC_BOUNCER_KEY=$API_KEY" >> .env
fi

# Update the bouncer config file with the API key
BOUNCER_CONFIG="./configs/angie/bouncers/crowdsec-nginx-bouncer.conf"
if [ -f "$BOUNCER_CONFIG" ]; then
  sed -i "s/API_KEY=.*/API_KEY=$API_KEY/" "$BOUNCER_CONFIG"
  echo "Updated bouncer config with API key"
else
  echo "WARNING: Bouncer config not found at $BOUNCER_CONFIG"
fi

echo "CrowdSec bouncer registered with API key: $API_KEY"
echo "Please restart the angie service: docker-compose restart angie"
