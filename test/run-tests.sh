#!/usr/bin/env bash
# shellcheck disable=SC1090

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
SCRIPT="${REPO_ROOT}/wireguard-install.sh"

TEST_TMP=$(mktemp -d)
trap 'rm -rf "${TEST_TMP}"' EXIT

export WG_DIR="${TEST_TMP}/wireguard"
export PARAMS_FILE="${WG_DIR}/params"
export LOG_FILE=""
export OUTPUT_FORMAT="table"

pass() {
	echo "ok - $1"
}

fail() {
	echo "not ok - $1" >&2
	if [[ -f ${TEST_TMP}/stdout ]]; then
		echo "--- stdout ---" >&2
		cat "${TEST_TMP}/stdout" >&2
	fi
	if [[ -f ${TEST_TMP}/stderr ]]; then
		echo "--- stderr ---" >&2
		cat "${TEST_TMP}/stderr" >&2
	fi
	exit 1
}

assert_success() {
	local name="$1"
	shift
	if "$@" >"${TEST_TMP}/stdout" 2>"${TEST_TMP}/stderr"; then
		pass "$name"
	else
		fail "$name"
	fi
}

assert_true() {
	local name="$1"
	shift
	if "$@"; then
		pass "$name"
	else
		fail "$name"
	fi
}

assert_false() {
	local name="$1"
	shift
	if "$@"; then
		fail "$name"
	else
		pass "$name"
	fi
}

assert_eq() {
	local name="$1"
	local expected="$2"
	local actual="$3"

	if [[ $actual == "$expected" ]]; then
		pass "$name"
	else
		echo "expected: $expected" >"${TEST_TMP}/stdout"
		echo "actual:   $actual" >>"${TEST_TMP}/stdout"
		fail "$name"
	fi
}

assert_file_contains() {
	local name="$1"
	local file="$2"
	local pattern="$3"

	if grep -Fq -- "$pattern" "$file"; then
		pass "$name"
	else
		echo "missing pattern: $pattern" >"${TEST_TMP}/stdout"
		echo "file: $file" >>"${TEST_TMP}/stdout"
		sed -n '1,160p' "$file" >>"${TEST_TMP}/stdout"
		fail "$name"
	fi
}

assert_file_not_contains() {
	local name="$1"
	local file="$2"
	local pattern="$3"

	if grep -Fq -- "$pattern" "$file"; then
		echo "unexpected pattern: $pattern" >"${TEST_TMP}/stdout"
		echo "file: $file" >>"${TEST_TMP}/stdout"
		fail "$name"
	else
		pass "$name"
	fi
}

assert_fails() {
	local name="$1"
	shift
	if "$@" >"${TEST_TMP}/stdout" 2>"${TEST_TMP}/stderr"; then
		fail "$name"
	else
		pass "$name"
	fi
}

load_script_functions() {
	local library_file="${TEST_TMP}/wireguard-install-lib.sh"
	awk '$0 != "main \"$@\"" { print }' "$SCRIPT" >"$library_file"
	source "$library_file"
}

write_fake_commands() {
	local bin_dir="${TEST_TMP}/bin"
	mkdir -p "$bin_dir"
	PATH="${bin_dir}:$PATH"
	export PATH

	cat >"${bin_dir}/systemctl" <<'EOF'
#!/bin/sh
if [ "$1" = "is-active" ] && [ "$2" = "--quiet" ]; then
	[ "$3" = "$FAKE_ACTIVE_SERVICE" ]
	exit $?
fi
exit 1
EOF
	chmod +x "${bin_dir}/systemctl"

	cat >"${bin_dir}/firewall-cmd" <<'EOF'
#!/bin/sh
exit 0
EOF
	chmod +x "${bin_dir}/firewall-cmd"

	cat >"${bin_dir}/nft" <<'EOF'
#!/bin/sh
exit 0
EOF
	chmod +x "${bin_dir}/nft"
}

set_common_config() {
	SERVER_PUB_IP="vpn.example.com"
	SERVER_PUB_NIC="eth0"
	SERVER_WG_NIC="wg0"
	SERVER_WG_IPV4="10.66.66.1"
	SERVER_WG_IPV6="fd42:42:42::1"
	SERVER_PORT="51820"
	SERVER_PRIV_KEY="server-private-key"
	SERVER_PUB_KEY="server-public-key"
	CLIENT_IPV4="y"
	CLIENT_IPV6="y"
	CLIENT_DNS_1="1.1.1.1"
	CLIENT_DNS_2="2606:4700:4700::1111"
	ALLOWED_IPS="0.0.0.0/0,::/0"
	MTU="1420"
	FIREWALL_BACKEND="iptables"
}

assert_success "top-level help" bash "$SCRIPT" --no-log --no-color --help
assert_file_contains "top-level help mentions install" "${TEST_TMP}/stdout" "install       Install and configure WireGuard"
assert_success "install help" bash "$SCRIPT" --no-log --no-color install --help
assert_file_contains "install help mentions endpoint" "${TEST_TMP}/stdout" "--endpoint <host>"
assert_success "client add help" bash "$SCRIPT" --no-log --no-color client add --help
assert_file_contains "client add help mentions output path" "${TEST_TMP}/stdout" "--output <path>"
assert_success "server status help" bash "$SCRIPT" --no-log --no-color server status --help
assert_file_contains "server status help mentions json" "${TEST_TMP}/stdout" "--format <fmt>"
assert_file_not_contains "installer avoids Arch package database sync" "$SCRIPT" "pacman -Sy &>/dev/null"
assert_file_not_contains "installer avoids unattended Arch full upgrade" "$SCRIPT" "pacman --needed --noconfirm -Syu"

load_script_functions
write_fake_commands
set_common_config

rpm_curl_minimal_bin="${TEST_TMP}/rpm-curl-minimal-bin"
mkdir -p "$rpm_curl_minimal_bin"
cat >"${rpm_curl_minimal_bin}/dnf" <<'EOF'
#!/bin/sh
echo "package:$3:" >>"$FAKE_PKG_LOG"
if [ "$1" = "install" ] && [ "$2" = "-y" ] && [ "$3" = "curl-minimal" ]; then
	printf '%s\n' '#!/bin/sh' 'exit 0' >"$FAKE_BIN/curl"
	/bin/chmod +x "$FAKE_BIN/curl"
	exit 0
fi
exit 1
EOF
chmod +x "${rpm_curl_minimal_bin}/dnf"
if (
	PATH="$rpm_curl_minimal_bin"
	export PATH
	FAKE_BIN="$rpm_curl_minimal_bin"
	FAKE_PKG_LOG="${TEST_TMP}/rpm-curl-minimal.log"
	export FAKE_BIN FAKE_PKG_LOG
	OS=fedora
	installCurlCommand
) >"${TEST_TMP}/stdout" 2>"${TEST_TMP}/stderr"; then
	pass "RPM curl helper installs curl-minimal when curl is missing"
else
	fail "RPM curl helper installs curl-minimal when curl is missing"
fi
assert_file_contains "RPM curl helper prefers curl-minimal" "${TEST_TMP}/rpm-curl-minimal.log" "package:curl-minimal:"
assert_file_not_contains "RPM curl helper avoids full curl when minimal works" "${TEST_TMP}/rpm-curl-minimal.log" "package:curl:"

rpm_curl_fallback_bin="${TEST_TMP}/rpm-curl-fallback-bin"
mkdir -p "$rpm_curl_fallback_bin"
cat >"${rpm_curl_fallback_bin}/dnf" <<'EOF'
#!/bin/sh
echo "package:$3:" >>"$FAKE_PKG_LOG"
if [ "$1" = "install" ] && [ "$2" = "-y" ] && [ "$3" = "curl" ]; then
	printf '%s\n' '#!/bin/sh' 'exit 0' >"$FAKE_BIN/curl"
	/bin/chmod +x "$FAKE_BIN/curl"
	exit 0
fi
exit 1
EOF
chmod +x "${rpm_curl_fallback_bin}/dnf"
if (
	PATH="$rpm_curl_fallback_bin"
	export PATH
	FAKE_BIN="$rpm_curl_fallback_bin"
	FAKE_PKG_LOG="${TEST_TMP}/rpm-curl-fallback.log"
	export FAKE_BIN FAKE_PKG_LOG
	OS=fedora
	installCurlCommand
) >"${TEST_TMP}/stdout" 2>"${TEST_TMP}/stderr"; then
	pass "RPM curl helper falls back to full curl when curl-minimal is unavailable"
else
	fail "RPM curl helper falls back to full curl when curl-minimal is unavailable"
fi
assert_file_contains "RPM curl helper tries curl-minimal first" "${TEST_TMP}/rpm-curl-fallback.log" "package:curl-minimal:"
assert_file_contains "RPM curl helper can fall back to full curl" "${TEST_TMP}/rpm-curl-fallback.log" "package:curl:"

assert_true "version_ge accepts newer version" version_ge "2.1" "2.0"
assert_true "version_ge accepts equal version" version_ge "2.0" "2.0"
assert_false "version_ge rejects older version" version_ge "1.9" "2.0"

assert_true "valid IPv4 accepted" is_valid_ipv4 "10.66.66.1"
assert_false "invalid IPv4 rejected" is_valid_ipv4 "999.66.66.1"
assert_true "valid IPv6 accepted" is_valid_ipv6 "fd42:42:42::1"
assert_false "invalid IPv6 rejected" is_valid_ipv6 "not-an-ip"
assert_true "valid client name accepted" is_valid_client_name "alice_01-prod"
assert_false "invalid client name rejected" is_valid_client_name "alice.example"
assert_true "valid interface name accepted" is_valid_interface_name "wg0"
assert_false "long interface name rejected" is_valid_interface_name "wireguardinterface"

assert_eq "compact IPv6 network" "fd42:42:42::" "$(get_ipv6_network "fd42:42:42::1")"
assert_eq "expanded IPv6 network" "fd42:42:42:42::" "$(get_ipv6_network "fd42:42:42:42::1")"
assert_eq "IPv4 server address list" "10.66.66.1/24" "$(CLIENT_IPV4=y CLIENT_IPV6=n buildAddressList)"
assert_eq "dual-stack client address list" "10.66.66.2/32,fd42:42:42::2/128" "$(CLIENT_IPV4=y CLIENT_IPV6=y CLIENT_WG_IPV4=10.66.66.2 CLIENT_WG_IPV6=fd42:42:42::2 buildClientAddressList)"
assert_eq "dual-stack DNS list" "1.1.1.1,2606:4700:4700::1111" "$(buildDnsList)"
assert_eq "hostname endpoint" "vpn.example.com:51820" "$(normalizeEndpoint)"
assert_eq "IPv6 endpoint gets brackets" "[2001:db8::1]:51820" "$(SERVER_PUB_IP=2001:db8::1 normalizeEndpoint)"

if (
	set_common_config
	validate_configuration
) >"${TEST_TMP}/stdout" 2>"${TEST_TMP}/stderr"; then
	pass "valid configuration passes"
else
	fail "valid configuration passes"
fi

if (
	set_common_config
	SERVER_PORT=99999
	validate_configuration
) >"${TEST_TMP}/stdout" 2>"${TEST_TMP}/stderr"; then
	fail "invalid configuration fails"
else
	pass "invalid configuration fails"
fi

set_common_config
writeParams
assert_file_contains "params file writes interface" "$PARAMS_FILE" "SERVER_WG_NIC=wg0"
assert_file_contains "params file writes MTU" "$PARAMS_FILE" "MTU=1420"

rm -f "${WG_DIR}/add-wg0-rules.sh" "${WG_DIR}/rm-wg0-rules.sh"
FAKE_ACTIVE_SERVICE="firewalld"
export FAKE_ACTIVE_SERVICE
createFirewallScripts
assert_eq "firewalld backend selected" "firewalld" "$FIREWALL_BACKEND"
assert_file_contains "firewalld add script opens port" "${WG_DIR}/add-wg0-rules.sh" "firewall-cmd --add-port=51820/udp"
assert_file_contains "firewalld remove script removes interface" "${WG_DIR}/rm-wg0-rules.sh" "firewall-cmd --zone=public --remove-interface=wg0"

rm -f "${WG_DIR}/add-wg0-rules.sh" "${WG_DIR}/rm-wg0-rules.sh"
FAKE_ACTIVE_SERVICE="nftables"
createFirewallScripts
assert_eq "nftables backend selected" "nftables" "$FIREWALL_BACKEND"
assert_file_contains "nftables add script creates table" "${WG_DIR}/add-wg0-rules.sh" "nft add table inet wireguard_wg0"
assert_file_contains "nftables remove script deletes table" "${WG_DIR}/rm-wg0-rules.sh" "nft delete table inet wireguard_wg0"

rm -f "${WG_DIR}/add-wg0-rules.sh" "${WG_DIR}/rm-wg0-rules.sh"
FAKE_ACTIVE_SERVICE="none"
FIREWALL_BACKEND_OVERRIDE="nftables"
createFirewallScripts
assert_eq "firewall backend override selected" "nftables" "$FIREWALL_BACKEND"
assert_file_contains "firewall backend override creates nft rules" "${WG_DIR}/add-wg0-rules.sh" "nft add table inet wireguard_wg0"
unset FIREWALL_BACKEND_OVERRIDE

rm -f "${WG_DIR}/add-wg0-rules.sh" "${WG_DIR}/rm-wg0-rules.sh"
FAKE_ACTIVE_SERVICE="none"
createFirewallScripts
assert_eq "iptables backend selected" "iptables" "$FIREWALL_BACKEND"
assert_file_contains "iptables add script opens port" "${WG_DIR}/add-wg0-rules.sh" "iptables -I INPUT -i eth0 -p udp --dport 51820 -j ACCEPT"
assert_file_contains "iptables remove script removes NAT" "${WG_DIR}/rm-wg0-rules.sh" "iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE"

echo "All tests passed."
