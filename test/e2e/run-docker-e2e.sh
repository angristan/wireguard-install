#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)

SERVER_BASE_IMAGE=${SERVER_BASE_IMAGE:-${BASE_IMAGE:-ubuntu:24.04}}
CLIENT_BASE_IMAGE=${CLIENT_BASE_IMAGE:-ubuntu:24.04}
CLIENT_IPV6=${CLIENT_IPV6:-n}
FULL_TUNNEL_TEST=${FULL_TUNNEL_TEST:-n}
ENABLE_NFTABLES=${ENABLE_NFTABLES:-n}
FIREWALL_BACKEND_OVERRIDE=${FIREWALL_BACKEND_OVERRIDE:-}
RUN_ID=${RUN_ID:-$(date +%s)-$$}
NETWORK="wireguard-e2e-${RUN_ID}"
CLIENT_NETWORK="wireguard-e2e-client-${RUN_ID}"
VOLUME="wireguard-e2e-shared-${RUN_ID}"
SERVER_IMAGE="wireguard-e2e-server:${RUN_ID}"
CLIENT_IMAGE="wireguard-e2e-client:${RUN_ID}"
SERVER_CONTAINER="wireguard-e2e-server-${RUN_ID}"
PROBE_CONTAINER="wireguard-e2e-probe-${RUN_ID}"
FULL_TUNNEL_IPV4=${FULL_TUNNEL_IPV4:-172.29.0.30}
WG_ENDPOINT=${WG_ENDPOINT:-wireguard-server}

cleanup() {
	docker rm -f "$PROBE_CONTAINER" >/dev/null 2>&1 || true
	docker rm -f "$SERVER_CONTAINER" >/dev/null 2>&1 || true
	docker volume rm "$VOLUME" >/dev/null 2>&1 || true
	docker network rm "$CLIENT_NETWORK" >/dev/null 2>&1 || true
	docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$REPO_ROOT"

if ! docker info >/dev/null 2>&1; then
	echo "Docker is not available." >&2
	exit 1
fi

if [[ $ENABLE_NFTABLES == "y" && -z $FIREWALL_BACKEND_OVERRIDE ]]; then
	FIREWALL_BACKEND_OVERRIDE=nftables
fi
if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	WG_ENDPOINT=host.docker.internal
fi

echo "Building E2E server image from ${SERVER_BASE_IMAGE}..."
docker build \
	--build-arg "BASE_IMAGE=${SERVER_BASE_IMAGE}" \
	--build-arg "ENABLE_NFTABLES=${ENABLE_NFTABLES}" \
	-t "$SERVER_IMAGE" \
	-f test/e2e/Dockerfile.server .
echo "Building E2E client image from ${CLIENT_BASE_IMAGE}..."
docker build \
	--build-arg "BASE_IMAGE=${CLIENT_BASE_IMAGE}" \
	-t "$CLIENT_IMAGE" \
	-f test/e2e/Dockerfile.client .

echo "Creating Docker network and shared volume..."
docker network create --subnet=172.29.0.0/24 "$NETWORK" >/dev/null
if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	docker network create --subnet=172.30.0.0/24 "$CLIENT_NETWORK" >/dev/null
fi
docker volume create "$VOLUME" >/dev/null

if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	echo "Starting full-tunnel probe container..."
	docker run -d \
		--name "$PROBE_CONTAINER" \
		--network "$NETWORK" \
		--ip "$FULL_TUNNEL_IPV4" \
		busybox tail -f /dev/null >/dev/null
fi

echo "Starting WireGuard server container..."
server_run_args=(
	-d
	--name "$SERVER_CONTAINER"
	--hostname wireguard-server
	--privileged
	--network "$NETWORK"
	--network-alias wireguard-server
	--ip 172.29.0.10
	-v "${VOLUME}:/shared"
	-e "CLIENT_IPV6=${CLIENT_IPV6}"
	-e "FULL_TUNNEL_TEST=${FULL_TUNNEL_TEST}"
	-e "FIREWALL_BACKEND_OVERRIDE=${FIREWALL_BACKEND_OVERRIDE}"
	-e "WG_ENDPOINT=${WG_ENDPOINT}"
)
if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	server_run_args+=(-p 51820:51820/udp)
fi
server_run_args+=("$SERVER_IMAGE")
docker run "${server_run_args[@]}" >/dev/null

echo "Waiting for server container..."
for i in {1..180}; do
	if docker run --rm -v "${VOLUME}:/shared" busybox test -f /shared/server-ready >/dev/null 2>&1; then
		break
	fi

	if ! docker ps --format '{{.Names}}' | grep -qx "$SERVER_CONTAINER"; then
		echo "Server container exited unexpectedly." >&2
		docker logs "$SERVER_CONTAINER" >&2 || true
		exit 1
	fi

	echo "Waiting... ($i/180)"
	sleep 1
done

if ! docker run --rm -v "${VOLUME}:/shared" busybox test -f /shared/server-ready >/dev/null 2>&1; then
	echo "Timed out waiting for server readiness." >&2
	docker logs "$SERVER_CONTAINER" >&2 || true
	exit 1
fi

echo "Running WireGuard client container..."
client_run_args=(
	--rm
	--name "wireguard-e2e-client-${RUN_ID}"
	--hostname wireguard-client
	--privileged
	-v "${VOLUME}:/shared"
	-e "CLIENT_IPV6=${CLIENT_IPV6}"
	-e "FULL_TUNNEL_TEST=${FULL_TUNNEL_TEST}"
	-e "FULL_TUNNEL_IPV4=${FULL_TUNNEL_IPV4}"
)
if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	client_run_args+=(
		--network "$CLIENT_NETWORK"
		--ip 172.30.0.20
		--add-host host.docker.internal:host-gateway
	)
else
	client_run_args+=(
		--network "$NETWORK"
		--ip 172.29.0.20
	)
fi
client_run_args+=("$CLIENT_IMAGE")
docker run "${client_run_args[@]}"

echo "Server logs:"
docker logs "$SERVER_CONTAINER"

echo "Docker E2E passed."
