#!/bin/bash

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
  -X POST "https://commonsecure.unicc.org/events/restSearch" \
  -H 'authorization: '${MISP_KEY} \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"timestamp": "15d", "published": true, "returnFormat": "stix2"}'
