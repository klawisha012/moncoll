#!/bin/bash
# Script to initialize CrowdSec and register the bouncer

set -e

echo "Initializing CrowdSec..."

# Wait for CrowdSec to be ready
until docker exec crowdsec cscli version > /dev/null 2>&1; do
  echo "Waiting for CrowdSec to start..."
  sleep 2
done

# Register the nginx bouncer
echo "Registering nginx bouncer..."
API_KEY=$(docker exec crowdsec cscli bouncers add nginx-bouncer -o raw)

# Update .env file with the API key
if grep -q "CROWDSEC_BOUNCER_KEY" .env; then
  sed -i "s/CROWDSEC_BOUNCER_KEY=.*/CROWDSEC_BOUNCER_KEY=$API_KEY/" .env
else
  echo "CROWDSEC_BOUNCER_KEY=$API_KEY" >> .env
fi

echo "CrowdSec bouncer registered with API key: $API_KEY"
echo "Please restart the angie service: docker-compose restart angie"
