#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run the native_sim firmware against a local Mosquitto broker over TLS.
# Both containers sit on an *internal* Docker network: no internet access.
# Called by `make run`; all settings come from the environment.
set -euo pipefail

: "${MOSQUITTO_REF:?}" "${IMAGE:?}" "${EXE:?}" "${NET_NAME:?}" "${BROKER_NAME:?}"
: "${RUN_SECONDS:=6}" "${HOST_UID:?}" "${HOST_GID:?}" "${REPO:?}"

docker network inspect "${NET_NAME}" >/dev/null 2>&1 \
  || docker network create --internal "${NET_NAME}" >/dev/null
docker rm -f "${BROKER_NAME}" >/dev/null 2>&1 || true
trap 'docker rm -f "${BROKER_NAME}" >/dev/null 2>&1 || true' EXIT

docker run -d --rm --name "${BROKER_NAME}" --network "${NET_NAME}" --network-alias mosquitto \
  -u "${HOST_UID}:${HOST_GID}" \
  -v "${REPO}/broker/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro" \
  -v "${REPO}/certs/generated:/mosquitto/certs:ro" \
  "${MOSQUITTO_REF}" >/dev/null

# Subscriber inside the broker container, verifying the broker with the demo CA.
sleep 1
docker exec -d "${BROKER_NAME}" sh -c \
  'mosquitto_sub -h localhost -p 8883 --cafile /mosquitto/certs/demo-ca.crt -t "cra-demo/#" -v > /tmp/received.log 2>&1'
sleep 1

echo "=== device (native_sim, ${RUN_SECONDS}s)"
docker run --rm -u "${HOST_UID}:${HOST_GID}" --network "${NET_NAME}" \
  -v "${REPO}:/ws/demo:ro" -w /ws/demo "${IMAGE}" "${EXE}" -stop_at="${RUN_SECONDS}"

sleep 1
echo "=== broker received"
docker exec "${BROKER_NAME}" cat /tmp/received.log
if ! docker exec "${BROKER_NAME}" grep -q '"seq":0' /tmp/received.log; then
  echo "=== broker log (no messages received)"
  docker logs "${BROKER_NAME}" 2>&1 | tail -15
  exit 1
fi
