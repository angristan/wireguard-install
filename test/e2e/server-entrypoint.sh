#!/usr/bin/env bash

set -euo pipefail

WG_INTERFACE=${WG_INTERFACE:-wg0}
WG_PORT=${WG_PORT:-51820}
WG_SERVER_IPV4=${WG_SERVER_IPV4:-10.77.0.1}
WG_CLIENT_IPV4=${WG_CLIENT_IPV4:-10.77.0.2}
WG_SERVER_IPV6=${WG_SERVER_IPV6:-fd77:77:77::1}
WG_CLIENT_IPV6=${WG_CLIENT_IPV6:-fd77:77:77::2}
WG_ENDPOINT=${WG_ENDPOINT:-wireguard-server}
CLIENT_NAME=${CLIENT_NAME:-testclient}
CLIENT_CONFIG=${CLIENT_CONFIG:-/shared/testclient.conf}
CLIENT_IPV6=${CLIENT_IPV6:-n}
FULL_TUNNEL_TEST=${FULL_TUNNEL_TEST:-n}
WG_ALLOWED_IPV4=${WG_ALLOWED_IPV4:-${WG_SERVER_IPV4%.*}.0/24}
WG_ALLOWED_IPV6=${WG_ALLOWED_IPV6:-fd77:77:77::/64}

echo "=== WireGuard server E2E ==="

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

echo "Running WireGuard installer..."
install_args=(
	--no-log
	--no-color
	install
	--endpoint "$WG_ENDPOINT"
	--public-interface eth0
	--wg-interface "$WG_INTERFACE"
	--server-ipv4 "$WG_SERVER_IPV4"
	--port "$WG_PORT"
	--client "$CLIENT_NAME"
	--output "$CLIENT_CONFIG"
)
if [[ $CLIENT_IPV6 == "y" ]]; then
	install_args+=(
		--server-ipv6 "$WG_SERVER_IPV6"
		--client-ipv6
	)
	if [[ $FULL_TUNNEL_TEST == "n" ]]; then
		install_args+=(--allowed-ips "${WG_ALLOWED_IPV4},${WG_ALLOWED_IPV6}")
	fi
else
	install_args+=(--no-client-ipv6)
	if [[ $FULL_TUNNEL_TEST == "n" ]]; then
		install_args+=(--allowed-ips "$WG_ALLOWED_IPV4")
	fi
fi

/opt/wireguard-install.sh "${install_args[@]}"

echo "Validating generated server files..."
test -f "/etc/wireguard/${WG_INTERFACE}.conf"
test -f /etc/wireguard/params
test -f "$CLIENT_CONFIG"
grep -Fq "Address = ${WG_SERVER_IPV4}/24" "/etc/wireguard/${WG_INTERFACE}.conf"
grep -Fq "ListenPort = ${WG_PORT}" "/etc/wireguard/${WG_INTERFACE}.conf"
grep -Fq "Endpoint = ${WG_ENDPOINT}:${WG_PORT}" "$CLIENT_CONFIG"
grep -Fq "Address = ${WG_CLIENT_IPV4}/32" "$CLIENT_CONFIG"
grep -Fq "DNS = " "$CLIENT_CONFIG"
if [[ $FULL_TUNNEL_TEST == "y" ]]; then
	if [[ $CLIENT_IPV6 == "y" ]]; then
		grep -Fq "AllowedIPs = 0.0.0.0/0,::/0" "$CLIENT_CONFIG"
	else
		grep -Fq "AllowedIPs = 0.0.0.0/0" "$CLIENT_CONFIG"
	fi
elif [[ $CLIENT_IPV6 == "n" ]]; then
	grep -Fq "AllowedIPs = ${WG_ALLOWED_IPV4}" "$CLIENT_CONFIG"
fi
if [[ $CLIENT_IPV6 == "y" ]]; then
	grep -Fq "Address = ${WG_SERVER_IPV4}/24,${WG_SERVER_IPV6}/64" "/etc/wireguard/${WG_INTERFACE}.conf"
	grep -Fq "Address = ${WG_CLIENT_IPV4}/32,${WG_CLIENT_IPV6}/128" "$CLIENT_CONFIG"
	if [[ $FULL_TUNNEL_TEST == "n" ]]; then
		grep -Fq "AllowedIPs = ${WG_ALLOWED_IPV4},${WG_ALLOWED_IPV6}" "$CLIENT_CONFIG"
	fi
fi

echo "Bringing up WireGuard interface..."
if ! ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
	wg-quick up "$WG_INTERFACE"
fi
wg show "$WG_INTERFACE"
ip address show "$WG_INTERFACE"

echo "Exercising client management commands..."
/opt/wireguard-install.sh --no-log --no-color client list --format json >/tmp/clients.json
grep -Fq "\"name\":\"${CLIENT_NAME}\"" /tmp/clients.json

/opt/wireguard-install.sh --no-log --no-color client add second --output /shared/second.conf
test -f /shared/second.conf
grep -Fq "### Client second" "/etc/wireguard/${WG_INTERFACE}.conf"

/opt/wireguard-install.sh --no-log --no-color client revoke second --force
if grep -Fq "### Client second" "/etc/wireguard/${WG_INTERFACE}.conf"; then
	echo "Client second still present after revoke" >&2
	exit 1
fi

touch /shared/server-ready
echo "WireGuard server E2E setup complete."

tail -f /dev/null
