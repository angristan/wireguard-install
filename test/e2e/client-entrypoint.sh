#!/usr/bin/env bash

set -euo pipefail

CLIENT_CONFIG=${CLIENT_CONFIG:-/shared/testclient.conf}
SERVER_READY=${SERVER_READY:-/shared/server-ready}
WG_SERVER_IPV4=${WG_SERVER_IPV4:-10.77.0.1}
WG_SERVER_IPV6=${WG_SERVER_IPV6:-fd77:77:77::1}
WG_INTERFACE=${WG_INTERFACE:-testclient}
CLIENT_IPV6=${CLIENT_IPV6:-n}
FULL_TUNNEL_TEST=${FULL_TUNNEL_TEST:-n}
FULL_TUNNEL_IPV4=${FULL_TUNNEL_IPV4:-172.29.0.30}

echo "=== WireGuard client E2E ==="

if [[ $CLIENT_IPV6 != "y" && $CLIENT_IPV6 != "n" ]]; then
	echo "CLIENT_IPV6 must be y or n." >&2
	exit 1
fi
if [[ $FULL_TUNNEL_TEST != "y" && $FULL_TUNNEL_TEST != "n" ]]; then
	echo "FULL_TUNNEL_TEST must be y or n." >&2
	exit 1
fi

if [[ ! -c /dev/net/tun ]]; then
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
	chmod 600 /dev/net/tun
fi

echo "Waiting for server readiness..."
for i in {1..120}; do
	if [[ -f $SERVER_READY && -f $CLIENT_CONFIG ]]; then
		break
	fi
	echo "Waiting... ($i/120)"
	sleep 1
done

if [[ ! -f $SERVER_READY || ! -f $CLIENT_CONFIG ]]; then
	echo "Server did not become ready." >&2
	exit 1
fi

cp "$CLIENT_CONFIG" "/tmp/${WG_INTERFACE}.conf"
# Minimal containers do not run a DNS manager. The generated config is validated
# on the server side; this test only needs the tunnel route.
sed -i '/^DNS = /d' "/tmp/${WG_INTERFACE}.conf"

echo "Bringing up client tunnel..."
wg-quick up "/tmp/${WG_INTERFACE}.conf"
trap 'wg-quick down "/tmp/${WG_INTERFACE}.conf" >/dev/null 2>&1 || true' EXIT

echo "Waiting for tunnel connectivity..."
tunnel_ready=false
for i in {1..30}; do
	if ping -c 1 -W 2 "$WG_SERVER_IPV4" >/dev/null 2>&1; then
		echo "Ping through tunnel succeeded."
		if [[ $CLIENT_IPV6 == "n" ]] || ping -6 -c 1 -W 2 "$WG_SERVER_IPV6" >/dev/null 2>&1; then
			[[ $CLIENT_IPV6 == "y" ]] && echo "IPv6 ping through tunnel succeeded."
			tunnel_ready=true
			break
		fi
	fi
	echo "Ping retry $i/30"
	sleep 1
done

if [[ $tunnel_ready != true ]]; then
	if [[ $CLIENT_IPV6 == "y" ]]; then
		echo "Could not reach $WG_SERVER_IPV4 and $WG_SERVER_IPV6 through WireGuard tunnel." >&2
	else
		echo "Could not reach $WG_SERVER_IPV4 through WireGuard tunnel." >&2
	fi
	wg show "$WG_INTERFACE" >&2 || true
	ip route >&2 || true
	ip -6 route >&2 || true
	exit 1
fi

if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	echo "Checking full-tunnel NAT connectivity..."
	for i in {1..30}; do
		if ping -c 1 -W 2 "$FULL_TUNNEL_IPV4" >/dev/null 2>&1; then
			echo "Full-tunnel NAT ping succeeded."
			wg show "$WG_INTERFACE"
			exit 0
		fi
		echo "Full-tunnel NAT retry $i/30"
		sleep 1
	done

	echo "Could not reach $FULL_TUNNEL_IPV4 through full-tunnel NAT." >&2
	wg show "$WG_INTERFACE" >&2 || true
	ip route >&2 || true
	ip -6 route >&2 || true
	exit 1
fi

wg show "$WG_INTERFACE"
