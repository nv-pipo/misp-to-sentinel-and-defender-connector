#!/bin/bash

if [ -z "$MISP_KEY" ]; then
  echo "MISP_KEY is not set. Please set it before running this script."
  exit 1
fi

set -v

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X GET https://commonsecure.unicc.org/servers/getVersion \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json"

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X POST "https://commonsecure.unicc.org/attributes/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "1d", "published": true, "returnFormat": "stix2"}'

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X POST "https://commonsecure.unicc.org/attributes/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "5d", "published": true, "returnFormat": "stix2"}'

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X POST "https://commonsecure.unicc.org/attributes/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "6d", "published": true, "returnFormat": "stix2"}'

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X POST "https://commonsecure.unicc.org/attributes/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "1d", "published": true, "returnFormat": "json"}'

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X POST "https://commonsecure.unicc.org/attributes/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "5d", "published": true, "returnFormat": "json"}'

curl -sS -O -w "\nResponse code: %{http_code}, Time: %{time_total}s\n" \
  -X POST "https://commonsecure.unicc.org/attributes/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "6d", "published": true, "returnFormat": "json"}'
