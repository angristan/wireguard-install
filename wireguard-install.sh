#!/bin/bash
# shellcheck disable=SC1090,SC1091,SC2034
# SC1090/SC1091: Not following /etc/os-release or /etc/wireguard/params (sourced dynamically)
# SC2034: Variables are used indirectly through configuration helpers and CLI state

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

readonly SCRIPT_NAME="wireguard-install"
readonly WG_DIR="${WG_DIR:-/etc/wireguard}"
readonly PARAMS_FILE="${PARAMS_FILE:-${WG_DIR}/params}"
readonly DEFAULT_SERVER_WG_NIC="wg0"
readonly DEFAULT_SERVER_WG_IPV4="10.66.66.1"
readonly DEFAULT_SERVER_WG_IPV6="fd42:42:42::1"
readonly DEFAULT_CLIENT_DNS_1="1.1.1.1"
readonly DEFAULT_CLIENT_DNS_2="1.0.0.1"
readonly DEFAULT_ALLOWED_IPS_IPV4="0.0.0.0/0"
readonly DEFAULT_ALLOWED_IPS_IPV6="::/0"
readonly MAX_INTERFACE_NAME_LENGTH=15
readonly MAX_CLIENT_NAME_LENGTH=64

# Logging configuration
# Set VERBOSE=1 to see command output, VERBOSE=0 (default) for quiet mode.
# Set LOG_FILE to customize log location, or LOG_FILE="" to disable file logging.
VERBOSE=${VERBOSE:-0}
LOG_FILE=${LOG_FILE-wireguard-install.log}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-table}

if [[ -t 1 ]] || [[ ${FORCE_COLOR:-0} == "1" ]]; then
	COLOR_RESET='\033[0m'
	COLOR_RED='\033[0;31m'
	COLOR_GREEN='\033[0;32m'
	COLOR_YELLOW='\033[0;33m'
	COLOR_BLUE='\033[0;34m'
	COLOR_CYAN='\033[0;36m'
	COLOR_DIM='\033[0;90m'
	COLOR_BOLD='\033[1m'
else
	COLOR_RESET=''
	COLOR_RED=''
	COLOR_GREEN=''
	COLOR_YELLOW=''
	COLOR_BLUE=''
	COLOR_CYAN=''
	COLOR_DIM=''
	COLOR_BOLD=''
fi

_log_to_file() {
	if [[ -n $LOG_FILE ]]; then
		echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG_FILE"
	fi
}

log_info() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
	_log_to_file "[INFO] $*"
}

log_warn() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
	_log_to_file "[WARN] $*"
}

log_error() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[ERROR] $*"
	if [[ -n $LOG_FILE ]]; then
		echo -e "${COLOR_YELLOW}        Check the log file for details: ${LOG_FILE}${COLOR_RESET}" >&2
	fi
}

log_fatal() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[FATAL] $*"
	if [[ -n $LOG_FILE ]]; then
		echo -e "${COLOR_YELLOW}        Check the log file for details: ${LOG_FILE}${COLOR_RESET}" >&2
		_log_to_file "Script exited with error"
	fi
	exit 1
}

log_success() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"
	_log_to_file "[OK] $*"
}

log_debug() {
	if [[ $VERBOSE -eq 1 && $OUTPUT_FORMAT != "json" ]]; then
		echo -e "${COLOR_DIM}[DEBUG]${COLOR_RESET} $*"
	fi
	_log_to_file "[DEBUG] $*"
}

log_prompt() {
	if [[ ${NON_INTERACTIVE_INSTALL:-n} != "y" ]]; then
		echo -e "${COLOR_CYAN}$*${COLOR_RESET}"
	fi
	_log_to_file "[PROMPT] $*"
}

log_header() {
	if [[ ${NON_INTERACTIVE_INSTALL:-n} != "y" && $OUTPUT_FORMAT != "json" ]]; then
		echo ""
		echo -e "${COLOR_BOLD}${COLOR_BLUE}=== $* ===${COLOR_RESET}"
		echo ""
	fi
	_log_to_file "=== $* ==="
}

log_menu() {
	if [[ ${NON_INTERACTIVE_INSTALL:-n} != "y" && $OUTPUT_FORMAT != "json" ]]; then
		echo "$@"
	fi
}

run_cmd() {
	local desc="$1"
	shift

	if [[ $OUTPUT_FORMAT != "json" ]]; then
		echo -e "${COLOR_DIM}> $*${COLOR_RESET}"
	fi
	_log_to_file "[CMD] $*"

	local ret
	if [[ $VERBOSE -eq 1 ]]; then
		if [[ -n $LOG_FILE ]]; then
			"$@" 2>&1 | tee -a "$LOG_FILE"
			ret=${PIPESTATUS[0]}
		else
			"$@"
			ret=$?
		fi
	else
		if [[ -n $LOG_FILE ]]; then
			"$@" >>"$LOG_FILE" 2>&1
			ret=$?
		else
			"$@" >/dev/null 2>&1
			ret=$?
		fi
	fi

	if [[ $ret -eq 0 ]]; then
		log_debug "$desc completed successfully"
	elif [[ ${RUN_CMD_WARN_ONLY:-0} == "1" ]]; then
		log_warn "$desc failed with exit code $ret"
	else
		log_error "$desc failed with exit code $ret"
	fi
	return "$ret"
}

run_cmd_optional() {
	local desc="$1"
	shift
	RUN_CMD_WARN_ONLY=1 run_cmd "$desc" "$@" || true
}

run_cmd_fatal() {
	local desc="$1"
	shift
	if ! run_cmd "$desc" "$@"; then
		log_fatal "$desc failed"
	fi
}

show_help() {
	cat <<-EOF
		WireGuard installer and manager

		Usage: $SCRIPT_NAME <command> [options]

		Commands:
			install       Install and configure WireGuard
			uninstall     Remove WireGuard and generated configuration
			client        Manage WireGuard clients
			server        Show server status
			interactive   Launch the interactive menu

		Global Options:
			--verbose     Show detailed command output
			--log <path>  Log file path (default: wireguard-install.log)
			--no-log      Disable file logging
			--no-color    Disable colored output
			-h, --help    Show help

		Run '$SCRIPT_NAME <command> --help' for command-specific help.
	EOF
}

show_install_help() {
	cat <<-EOF
		Install and configure WireGuard

		Usage: $SCRIPT_NAME install [options]

		Options:
			-i, --interactive       Run the interactive install wizard
			--endpoint <host>       Public IP or hostname for client configs
			--public-interface <if> Public network interface (auto-detected)
			--wg-interface <if>     WireGuard interface name (default: wg0)
			--server-ipv4 <addr>    Server WireGuard IPv4 (default: 10.66.66.1)
			--server-ipv6 <addr>    Server WireGuard IPv6 (default: fd42:42:42::1)
			--client-ipv4           Enable IPv4 client addressing (default)
			--no-client-ipv4        Disable IPv4 client addressing
			--client-ipv6           Enable IPv6 client addressing (default)
			--no-client-ipv6        Disable IPv6 client addressing
			--port <num>            WireGuard UDP port
			--port-random           Use a random port (49152-65535)
			--dns-primary <addr>    Primary client DNS resolver (default: 1.1.1.1)
			--dns-secondary <addr>  Secondary client DNS resolver (default: 1.0.0.1)
			--allowed-ips <list>    AllowedIPs for generated clients
			--mtu <size>            WireGuard MTU (576-65535)
			--client <name>         Initial client name (default: client)
			--output <path>         Output path for the initial client config
			--no-client             Skip initial client creation

		Examples:
			$SCRIPT_NAME install
			$SCRIPT_NAME install --endpoint vpn.example.com --port 51820
			$SCRIPT_NAME install --no-client-ipv6 --client alice --output /tmp/alice.conf
			$SCRIPT_NAME install -i
	EOF
}

show_uninstall_help() {
	cat <<-EOF
		Remove WireGuard

		Usage: $SCRIPT_NAME uninstall [options]

		Options:
			-f, --force   Skip confirmation prompt
	EOF
}

show_client_help() {
	cat <<-EOF
		Manage WireGuard clients

		Usage: $SCRIPT_NAME client <subcommand> [options]

		Subcommands:
			add <name>     Add a new client
			list           List clients
			revoke <name>  Revoke a client

		Run '$SCRIPT_NAME client <subcommand> --help' for more info.
	EOF
}

show_client_add_help() {
	cat <<-EOF
		Add a new WireGuard client

		Usage: $SCRIPT_NAME client add <name> [options]

		Options:
			--ipv4 <addr>    Client WireGuard IPv4
			--ipv6 <addr>    Client WireGuard IPv6
			--output <path>  Output path for client config
	EOF
}

show_client_list_help() {
	cat <<-EOF
		List WireGuard clients

		Usage: $SCRIPT_NAME client list [options]

		Options:
			--format <fmt>  Output format: table or json (default: table)
	EOF
}

show_client_revoke_help() {
	cat <<-EOF
		Revoke a WireGuard client

		Usage: $SCRIPT_NAME client revoke <name> [options]

		Options:
			-f, --force   Skip confirmation prompt
	EOF
}

show_server_help() {
	cat <<-EOF
		Server management

		Usage: $SCRIPT_NAME server <subcommand> [options]

		Subcommands:
			status   Show WireGuard peer status
	EOF
}

show_server_status_help() {
	cat <<-EOF
		Show WireGuard peer status

		Usage: $SCRIPT_NAME server status [options]

		Options:
			--format <fmt>  Output format: table or json (default: table)
	EOF
}

version_ge() {
	local ver1="$1"
	local ver2="$2"
	[[ "$(printf '%s\n%s' "$ver1" "$ver2" | sort -V | head -n1)" == "$ver2" ]]
}

json_escape() {
	local str="$1"
	str="${str//\\/\\\\}"
	str="${str//\"/\\\"}"
	str="${str//$'\n'/\\n}"
	str="${str//$'\r'/\\r}"
	str="${str//$'\t'/\\t}"
	printf '%s' "$str"
}

isRoot() {
	[[ $EUID -eq 0 ]]
}

isWireGuardInstalled() {
	[[ -e $PARAMS_FILE ]]
}

requireWireGuard() {
	if ! isWireGuardInstalled; then
		log_fatal "WireGuard is not installed. Run '$SCRIPT_NAME install' first."
	fi
}

requireNoWireGuard() {
	if isWireGuardInstalled; then
		log_fatal "WireGuard is already installed. Use '$SCRIPT_NAME client' to manage clients or '$SCRIPT_NAME uninstall' to remove it."
	fi
}

loadParams() {
	requireWireGuard
	source "$PARAMS_FILE"
	CLIENT_IPV4=${CLIENT_IPV4:-y}
	CLIENT_IPV6=${CLIENT_IPV6:-y}
	CLIENT_DNS_1=${CLIENT_DNS_1:-$DEFAULT_CLIENT_DNS_1}
	CLIENT_DNS_2=${CLIENT_DNS_2:-$DEFAULT_CLIENT_DNS_2}
}

checkVirt() {
	local virt=""
	if command -v virt-what &>/dev/null; then
		virt=$(virt-what)
	elif command -v systemd-detect-virt &>/dev/null; then
		virt=$(systemd-detect-virt)
	fi

	if [[ $virt == "openvz" ]]; then
		log_fatal "OpenVZ is not supported."
	fi
	if [[ $virt == "lxc" ]]; then
		log_fatal "LXC is not supported yet. WireGuard can run in LXC only when the host has the kernel module and the container is configured for it."
	fi
}

checkOS() {
	if [[ -e /etc/os-release ]]; then
		source /etc/os-release
	else
		log_fatal "Could not detect operating system: /etc/os-release is missing."
	fi

	OS="${ID}"
	case "$ID" in
	debian | raspbian)
		if ! version_ge "$VERSION_ID" "10"; then
			log_fatal "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later."
		fi
		OS=debian
		;;
	ubuntu)
		if ! version_ge "$VERSION_ID" "18.04"; then
			log_fatal "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later."
		fi
		;;
	fedora)
		if ! version_ge "$VERSION_ID" "32"; then
			log_fatal "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later."
		fi
		;;
	centos | almalinux | rocky | rhel)
		if ! version_ge "${VERSION_ID%%.*}" "8"; then
			log_fatal "Your version (${VERSION_ID}) is not supported. Please use version 8 or later."
		fi
		OS=centos
		;;
	ol)
		if ! version_ge "${VERSION_ID%%.*}" "8"; then
			log_fatal "Your version of Oracle Linux (${VERSION_ID}) is not supported. Please use version 8 or later."
		fi
		OS=oracle
		;;
	amzn)
		if [[ $PRETTY_NAME =~ ^Amazon\ Linux\ 2023 ]]; then
			OS=amzn2023
		else
			log_fatal "Your version of Amazon Linux is not supported. Please use Amazon Linux 2023."
		fi
		;;
	opensuse-tumbleweed)
		OS=opensuse
		;;
	opensuse-leap)
		OS=opensuse
		if ! version_ge "${VERSION_ID%%.*}" "15"; then
			log_fatal "Your version of openSUSE Leap (${VERSION_ID}) is not supported. Please use Leap 15 or later."
		fi
		;;
	arch)
		OS=arch
		;;
	alpine)
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			if ! (apk update && apk add virt-what) &>/dev/null; then
				log_warn "Failed to install virt-what. Continuing without virtualization check."
			fi
		fi
		;;
	*)
		if [[ -e /etc/arch-release ]]; then
			OS=arch
		elif [[ -e /etc/alpine-release ]]; then
			OS=alpine
		elif [[ -e /etc/oracle-release ]]; then
			OS=oracle
		else
			log_fatal "It looks like you aren't running this installer on a Debian, Ubuntu, Fedora, openSUSE, CentOS, Amazon Linux 2023, Oracle Linux, Arch Linux, Alpine Linux, Rocky Linux or AlmaLinux system."
		fi
		;;
	esac
}

checkArchPendingKernelUpgrade() {
	if [[ $OS != "arch" ]]; then
		return 0
	fi

	if [[ -f /.dockerenv ]] || grep -qE '(docker|lxc|containerd)' /proc/1/cgroup 2>/dev/null; then
		log_info "Running in a container, skipping Arch kernel module checks."
		return 0
	fi

	local running_kernel
	running_kernel=$(uname -r)
	if [[ ! -d "/lib/modules/${running_kernel}" ]]; then
		log_fatal "Kernel modules for the running kernel (${running_kernel}) were not found. Reboot before installing WireGuard."
	fi

	if ! command -v checkupdates &>/dev/null; then
		log_warn "checkupdates is not installed, skipping Arch pending kernel upgrade check to avoid mutating pacman databases."
		log_warn "Install pacman-contrib for this preflight check, or make sure the system is fully upgraded and rebooted before installing."
		return 0
	fi

	log_info "Checking for pending kernel upgrades on Arch Linux..."
	local updates checkupdates_status pending_kernels
	updates=$(checkupdates 2>/dev/null)
	checkupdates_status=$?
	if [[ $checkupdates_status -ne 0 && $checkupdates_status -ne 2 ]]; then
		log_warn "Unable to check pending Arch updates without mutating pacman databases, skipping kernel upgrade check."
		return 0
	fi

	pending_kernels=$(grep -E '^(linux|linux-lts|linux-zen|linux-hardened)[[:space:]]' <<<"$updates" || true)
	if [[ -n $pending_kernels ]]; then
		log_warn "Linux kernel upgrade(s) are pending:"
		while read -r line; do
			log_info "  $line"
		done <<<"$pending_kernels"
		log_fatal "Upgrade and reboot before running this script so WireGuard can load against the running kernel."
	fi

	log_success "No pending kernel upgrades."
}

initialCheck() {
	log_debug "Checking root privileges..."
	if ! isRoot; then
		log_fatal "Sorry, you need to run this script as root."
	fi

	log_debug "Detecting operating system..."
	checkOS
	log_debug "Detected OS: $OS (${PRETTY_NAME:-unknown})"

	checkVirt
}

is_valid_port() {
	local port="$1"
	[[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535))
}

validate_port() {
	if ! is_valid_port "$1"; then
		log_fatal "Invalid port: $1. Must be a number between 1 and 65535."
	fi
}

is_valid_mtu() {
	local mtu="$1"
	[[ $mtu =~ ^[0-9]+$ ]] && ((mtu >= 576 && mtu <= 65535))
}

validate_mtu() {
	if ! is_valid_mtu "$1"; then
		log_fatal "Invalid MTU: $1. Must be a number between 576 and 65535."
	fi
}

is_valid_client_name() {
	local name="$1"
	[[ $name =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#name} -le $MAX_CLIENT_NAME_LENGTH ]]
}

validate_client_name() {
	local name="$1"
	if [[ -z $name ]]; then
		log_fatal "Client name cannot be empty."
	fi
	if ! [[ $name =~ ^[a-zA-Z0-9_-]+$ ]]; then
		log_fatal "Invalid client name: $name. Only alphanumeric characters, underscores, and hyphens are allowed."
	fi
	if [[ ${#name} -gt $MAX_CLIENT_NAME_LENGTH ]]; then
		log_fatal "Client name too long: ${#name} characters. Maximum is $MAX_CLIENT_NAME_LENGTH."
	fi
}

is_valid_interface_name() {
	local name="$1"
	[[ $name =~ ^[a-zA-Z0-9_]+$ ]] && [[ ${#name} -le $MAX_INTERFACE_NAME_LENGTH ]]
}

validate_interface_name() {
	if ! is_valid_interface_name "$1"; then
		log_fatal "Invalid interface name: $1. Use alphanumeric characters or underscores, max $MAX_INTERFACE_NAME_LENGTH characters."
	fi
}

is_valid_ipv4() {
	local ip="$1"
	local octet
	[[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
	IFS='.' read -r -a octets <<<"$ip"
	for octet in "${octets[@]}"; do
		((octet >= 0 && octet <= 255)) || return 1
	done
}

is_valid_ipv6() {
	local ip="$1"
	[[ $ip =~ ^[0-9a-fA-F:]+$ ]] && [[ $ip == *:* ]]
}

is_valid_dns() {
	local dns="$1"
	[[ -z $dns ]] && return 0
	is_valid_ipv4 "$dns" || is_valid_ipv6 "$dns"
}

validate_configuration() {
	validate_interface_name "$SERVER_WG_NIC"
	validate_interface_name "$SERVER_PUB_NIC"
	validate_port "$SERVER_PORT"

	if [[ $CLIENT_IPV4 != "y" && $CLIENT_IPV6 != "y" ]]; then
		log_fatal "At least one of CLIENT_IPV4 or CLIENT_IPV6 must be enabled."
	fi

	if [[ $CLIENT_IPV4 == "y" ]] && ! is_valid_ipv4 "$SERVER_WG_IPV4"; then
		log_fatal "Invalid server WireGuard IPv4: $SERVER_WG_IPV4"
	fi
	if [[ $CLIENT_IPV6 == "y" ]] && ! is_valid_ipv6 "$SERVER_WG_IPV6"; then
		log_fatal "Invalid server WireGuard IPv6: $SERVER_WG_IPV6"
	fi
	if [[ -z $SERVER_PUB_IP ]]; then
		log_fatal "The public endpoint address is required."
	fi
	if ! is_valid_dns "$CLIENT_DNS_1"; then
		log_fatal "Invalid primary DNS resolver: $CLIENT_DNS_1"
	fi
	if ! is_valid_dns "$CLIENT_DNS_2"; then
		log_fatal "Invalid secondary DNS resolver: $CLIENT_DNS_2"
	fi
	if [[ -z $ALLOWED_IPS ]]; then
		log_fatal "AllowedIPs cannot be empty."
	fi
	if [[ -n ${MTU:-} ]]; then
		validate_mtu "$MTU"
	fi
}

get_ipv4_network() {
	local ip="$1"
	echo "${ip%.*}.0"
}

get_ipv6_network() {
	local ip="$1"
	if [[ $ip == *"::"* ]]; then
		echo "${ip%%::*}::"
	else
		IFS=':' read -r h1 h2 h3 h4 _ <<<"$ip"
		echo "${h1}:${h2}:${h3}:${h4}::"
	fi
}

is_private_ipv4() {
	local ip="$1"
	echo "$ip" | grep -qE '^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)'
}

resolvePublicIPv4() {
	local public_ip=""
	if command -v curl &>/dev/null; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://api.seeip.org 2>/dev/null || true)
		[[ -z $public_ip ]] && public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://ifconfig.me 2>/dev/null || true)
		[[ -z $public_ip ]] && public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://api.ipify.org 2>/dev/null || true)
	fi
	if [[ -z $public_ip ]] && command -v dig &>/dev/null; then
		public_ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi
	echo "$public_ip"
}

resolvePublicIPv6() {
	local public_ip=""
	if command -v curl &>/dev/null; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://api6.seeip.org 2>/dev/null || true)
		[[ -z $public_ip ]] && public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://ifconfig.me 2>/dev/null || true)
		[[ -z $public_ip ]] && public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://api64.ipify.org 2>/dev/null || true)
	fi
	if [[ -z $public_ip ]] && command -v dig &>/dev/null; then
		public_ip=$(dig -6 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi
	echo "$public_ip"
}

detect_server_network() {
	if ! command -v ip &>/dev/null; then
		DETECTED_IPV4=""
		DETECTED_IPV6=""
		DETECTED_NIC=""
		return
	fi

	DETECTED_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	DETECTED_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	DETECTED_NIC=$(ip -4 route show default | awk '/default/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)
	if [[ -z $DETECTED_NIC ]]; then
		DETECTED_NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p' | head -1)
	fi
}

has_ipv6_connectivity() {
	local ping_cmd
	if command -v ping6 &>/dev/null; then
		ping_cmd=(ping6 -c1 -W2 ipv6.google.com)
	else
		ping_cmd=(ping -6 -c1 -W2 ipv6.google.com)
	fi
	"${ping_cmd[@]}" >/dev/null 2>&1
}

set_installation_defaults() {
	detect_server_network

	SERVER_WG_NIC="${SERVER_WG_NIC:-$DEFAULT_SERVER_WG_NIC}"
	SERVER_PUB_NIC="${SERVER_PUB_NIC:-$DETECTED_NIC}"
	SERVER_WG_IPV4="${SERVER_WG_IPV4:-$DEFAULT_SERVER_WG_IPV4}"
	SERVER_WG_IPV6="${SERVER_WG_IPV6:-$DEFAULT_SERVER_WG_IPV6}"
	CLIENT_IPV4="${CLIENT_IPV4:-y}"
	CLIENT_IPV6="${CLIENT_IPV6:-y}"
	CLIENT_DNS_1="${CLIENT_DNS_1:-$DEFAULT_CLIENT_DNS_1}"
	CLIENT_DNS_2="${CLIENT_DNS_2:-$DEFAULT_CLIENT_DNS_2}"
	CLIENT_NAME="${CLIENT_NAME:-client}"
	NEW_CLIENT="${NEW_CLIENT:-y}"

	if [[ -z ${SERVER_PUB_IP:-} ]]; then
		if [[ -n $DETECTED_IPV4 ]]; then
			if is_private_ipv4 "$DETECTED_IPV4"; then
				SERVER_PUB_IP=$(resolvePublicIPv4)
			else
				SERVER_PUB_IP="$DETECTED_IPV4"
			fi
		elif [[ -n $DETECTED_IPV6 ]]; then
			SERVER_PUB_IP="$DETECTED_IPV6"
		fi
	fi

	if [[ -z ${SERVER_PORT:-} || ${SERVER_PORT:-} == "random" ]]; then
		SERVER_PORT=$(shuf -i 49152-65535 -n1)
		log_info "Random port: $SERVER_PORT"
	fi

	if [[ -z ${ALLOWED_IPS:-} ]]; then
		if [[ $CLIENT_IPV4 == "y" && $CLIENT_IPV6 == "y" ]]; then
			ALLOWED_IPS="${DEFAULT_ALLOWED_IPS_IPV4},${DEFAULT_ALLOWED_IPS_IPV6}"
		elif [[ $CLIENT_IPV4 == "y" ]]; then
			ALLOWED_IPS="$DEFAULT_ALLOWED_IPS_IPV4"
		else
			ALLOWED_IPS="$DEFAULT_ALLOWED_IPS_IPV6"
		fi
	fi
}

prompt_yes_no() {
	local prompt="$1"
	local default="$2"
	local -n result_ref="$3"

	until [[ $result_ref =~ ^[yn]$ ]]; do
		read -rp "$prompt [y/n]: " -e -i "$default" result_ref
	done
}

installQuestions() {
	log_header "WireGuard Installer"
	log_prompt "The git repository is available at: https://github.com/angristan/wireguard-install"
	log_prompt "I need to ask you a few questions before starting the setup."
	log_prompt "You can leave the default options and just press enter if you are okay with them."

	detect_server_network

	log_menu ""
	log_prompt "Detected network settings:"
	[[ -n $DETECTED_IPV4 ]] && log_menu "   IPv4: $DETECTED_IPV4"
	[[ -n $DETECTED_IPV6 ]] && log_menu "   IPv6: $DETECTED_IPV6"
	[[ -n $DETECTED_NIC ]] && log_menu "   Public interface: $DETECTED_NIC"

	local default_endpoint="$DETECTED_IPV4"
	if [[ -n $DETECTED_IPV4 ]] && is_private_ipv4 "$DETECTED_IPV4"; then
		default_endpoint=$(resolvePublicIPv4)
	fi
	if [[ -z $default_endpoint && -n $DETECTED_IPV6 ]]; then
		default_endpoint="$DETECTED_IPV6"
	fi

	until [[ -n $SERVER_PUB_IP ]]; do
		read -rp "IPv4 or IPv6 public address or hostname: " -e -i "$default_endpoint" SERVER_PUB_IP
	done

	until is_valid_interface_name "$SERVER_PUB_NIC"; do
		read -rp "Public interface: " -e -i "$DETECTED_NIC" SERVER_PUB_NIC
	done

	until is_valid_interface_name "$SERVER_WG_NIC"; do
		read -rp "WireGuard interface name: " -e -i "$DEFAULT_SERVER_WG_NIC" SERVER_WG_NIC
	done

	log_menu ""
	log_prompt "What IP versions should VPN clients use?"
	log_menu "   1) IPv4 only"
	log_menu "   2) IPv6 only"
	log_menu "   3) Dual-stack (IPv4 + IPv6)"
	local client_ip_default=1
	if has_ipv6_connectivity; then
		client_ip_default=3
	fi
	local client_ip_choice
	until [[ $client_ip_choice =~ ^[1-3]$ ]]; do
		read -rp "Client IP versions [1-3]: " -e -i "$client_ip_default" client_ip_choice
	done
	case "$client_ip_choice" in
	1)
		CLIENT_IPV4=y
		CLIENT_IPV6=n
		;;
	2)
		CLIENT_IPV4=n
		CLIENT_IPV6=y
		;;
	3)
		CLIENT_IPV4=y
		CLIENT_IPV6=y
		;;
	esac

	if [[ $CLIENT_IPV4 == "y" ]]; then
		until is_valid_ipv4 "$SERVER_WG_IPV4"; do
			read -rp "Server WireGuard IPv4: " -e -i "$DEFAULT_SERVER_WG_IPV4" SERVER_WG_IPV4
		done
	else
		SERVER_WG_IPV4="$DEFAULT_SERVER_WG_IPV4"
	fi

	if [[ $CLIENT_IPV6 == "y" ]]; then
		until is_valid_ipv6 "$SERVER_WG_IPV6"; do
			read -rp "Server WireGuard IPv6: " -e -i "$DEFAULT_SERVER_WG_IPV6" SERVER_WG_IPV6
		done
	else
		SERVER_WG_IPV6="$DEFAULT_SERVER_WG_IPV6"
	fi

	local random_port
	random_port=$(shuf -i 49152-65535 -n1)
	until is_valid_port "$SERVER_PORT"; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "$random_port" SERVER_PORT
	done

	until is_valid_dns "$CLIENT_DNS_1" && [[ -n $CLIENT_DNS_1 ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i "$DEFAULT_CLIENT_DNS_1" CLIENT_DNS_1
	done
	until is_valid_dns "$CLIENT_DNS_2"; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i "$DEFAULT_CLIENT_DNS_2" CLIENT_DNS_2
	done

	local default_allowed_ips
	if [[ $CLIENT_IPV4 == "y" && $CLIENT_IPV6 == "y" ]]; then
		default_allowed_ips="${DEFAULT_ALLOWED_IPS_IPV4},${DEFAULT_ALLOWED_IPS_IPV6}"
	elif [[ $CLIENT_IPV4 == "y" ]]; then
		default_allowed_ips="$DEFAULT_ALLOWED_IPS_IPV4"
	else
		default_allowed_ips="$DEFAULT_ALLOWED_IPS_IPV6"
	fi
	until [[ -n $ALLOWED_IPS ]]; do
		log_menu ""
		log_prompt "WireGuard uses AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients: " -e -i "$default_allowed_ips" ALLOWED_IPS
	done

	log_menu ""
	log_prompt "Do you want to customize the WireGuard MTU?"
	log_menu "   1) Default"
	log_menu "   2) Custom"
	local mtu_choice
	until [[ $mtu_choice =~ ^[1-2]$ ]]; do
		read -rp "MTU choice [1-2]: " -e -i 1 mtu_choice
	done
	if [[ $mtu_choice == "2" ]]; then
		until is_valid_mtu "$MTU"; do
			read -rp "MTU [576-65535]: " -e -i 1420 MTU
		done
	fi

	log_menu ""
	log_prompt "Okay, that was all I needed. We are ready to set up your WireGuard server now."
	log_prompt "You will be able to generate a client at the end of the installation."
	if [[ ${APPROVE_INSTALL:-n} =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

writeParams() {
	run_cmd_fatal "Creating WireGuard directory" mkdir -p "$WG_DIR"
	chmod 700 "$WG_DIR"
	{
		for param in \
			SERVER_PUB_IP \
			SERVER_PUB_NIC \
			SERVER_WG_NIC \
			SERVER_WG_IPV4 \
			SERVER_WG_IPV6 \
			SERVER_PORT \
			SERVER_PRIV_KEY \
			SERVER_PUB_KEY \
			CLIENT_IPV4 \
			CLIENT_IPV6 \
			CLIENT_DNS_1 \
			CLIENT_DNS_2 \
			ALLOWED_IPS \
			MTU \
			FIREWALL_BACKEND; do
			printf '%s=%q\n' "$param" "${!param:-}"
		done
	} >"$PARAMS_FILE"
	chmod 600 "$PARAMS_FILE"
}

getFirewallBackend() {
	case "${FIREWALL_BACKEND_OVERRIDE:-}" in
	firewalld)
		command -v firewall-cmd &>/dev/null || {
			echo "firewalld backend was requested but firewall-cmd is not available." >&2
			return 1
		}
		echo "firewalld"
		return 0
		;;
	nftables)
		command -v nft &>/dev/null || {
			echo "nftables backend was requested but nft is not available." >&2
			return 1
		}
		echo "nftables"
		return 0
		;;
	iptables)
		command -v iptables &>/dev/null || {
			echo "iptables backend was requested but iptables is not available." >&2
			return 1
		}
		echo "iptables"
		return 0
		;;
	"") ;;
	*)
		echo "Invalid firewall backend override: ${FIREWALL_BACKEND_OVERRIDE}. Use firewalld, nftables, or iptables." >&2
		return 1
		;;
	esac

	if command -v firewall-cmd &>/dev/null && command -v systemctl &>/dev/null && systemctl is-active --quiet firewalld >/dev/null 2>&1; then
		echo "firewalld"
	elif command -v nft &>/dev/null && command -v systemctl &>/dev/null && systemctl is-active --quiet nftables >/dev/null 2>&1; then
		echo "nftables"
	else
		echo "iptables"
	fi
}

createFirewallScripts() {
	local add_rules="${WG_DIR}/add-${SERVER_WG_NIC}-rules.sh"
	local rm_rules="${WG_DIR}/rm-${SERVER_WG_NIC}-rules.sh"
	local ipv4_network ipv6_network table_name nat_table_name

	ipv4_network=$(get_ipv4_network "$SERVER_WG_IPV4")
	ipv6_network=$(get_ipv6_network "$SERVER_WG_IPV6")
	table_name="wireguard_${SERVER_WG_NIC}"
	nat_table_name="${table_name}_nat"

	FIREWALL_BACKEND=$(getFirewallBackend) || log_fatal "Unable to determine firewall backend."
	log_info "Configuring firewall rules with $FIREWALL_BACKEND."

	case "$FIREWALL_BACKEND" in
	firewalld)
		cat >"$add_rules" <<-EOF
			#!/bin/sh
			set -e
			firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC}
			firewall-cmd --add-port=${SERVER_PORT}/udp
		EOF
		if [[ $CLIENT_IPV4 == "y" ]]; then
			echo "firewall-cmd --add-rich-rule='rule family=ipv4 source address=${ipv4_network}/24 masquerade'" >>"$add_rules"
		fi
		if [[ $CLIENT_IPV6 == "y" ]]; then
			echo "firewall-cmd --add-rich-rule='rule family=ipv6 source address=${ipv6_network}/64 masquerade'" >>"$add_rules"
		fi

		cat >"$rm_rules" <<-EOF
			#!/bin/sh
			firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC} 2>/dev/null || true
			firewall-cmd --remove-port=${SERVER_PORT}/udp 2>/dev/null || true
		EOF
		if [[ $CLIENT_IPV4 == "y" ]]; then
			echo "firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${ipv4_network}/24 masquerade' 2>/dev/null || true" >>"$rm_rules"
		fi
		if [[ $CLIENT_IPV6 == "y" ]]; then
			echo "firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${ipv6_network}/64 masquerade' 2>/dev/null || true" >>"$rm_rules"
		fi
		;;
	nftables)
		cat >"$add_rules" <<-EOF
			#!/bin/sh
			set -e
			nft delete table inet ${table_name} 2>/dev/null || true
			nft delete table ip ${nat_table_name} 2>/dev/null || true
			nft delete table ip6 ${nat_table_name} 2>/dev/null || true
			nft add table inet ${table_name}
			nft 'add chain inet ${table_name} input { type filter hook input priority 0; policy accept; }'
			nft 'add chain inet ${table_name} forward { type filter hook forward priority 0; policy accept; }'
			nft add rule inet ${table_name} input iifname "${SERVER_PUB_NIC}" udp dport ${SERVER_PORT} accept
			nft add rule inet ${table_name} forward iifname "${SERVER_WG_NIC}" accept
			nft add rule inet ${table_name} forward oifname "${SERVER_WG_NIC}" accept
		EOF
		if [[ $CLIENT_IPV4 == "y" ]]; then
			cat >>"$add_rules" <<-EOF
				nft add table ip ${nat_table_name}
				nft 'add chain ip ${nat_table_name} postrouting { type nat hook postrouting priority 100; policy accept; }'
				nft add rule ip ${nat_table_name} postrouting ip saddr ${ipv4_network}/24 oifname "${SERVER_PUB_NIC}" masquerade
			EOF
		fi
		if [[ $CLIENT_IPV6 == "y" ]]; then
			cat >>"$add_rules" <<-EOF
				nft add table ip6 ${nat_table_name}
				nft 'add chain ip6 ${nat_table_name} postrouting { type nat hook postrouting priority 100; policy accept; }'
				nft add rule ip6 ${nat_table_name} postrouting ip6 saddr ${ipv6_network}/64 oifname "${SERVER_PUB_NIC}" masquerade
			EOF
		fi
		cat >"$rm_rules" <<-EOF
			#!/bin/sh
			nft delete table inet ${table_name} 2>/dev/null || true
			nft delete table ip ${nat_table_name} 2>/dev/null || true
			nft delete table ip6 ${nat_table_name} 2>/dev/null || true
		EOF
		;;
	iptables)
		cat >"$add_rules" <<-EOF
			#!/bin/sh
			set -e
			iptables -I INPUT -i ${SERVER_PUB_NIC} -p udp --dport ${SERVER_PORT} -j ACCEPT
			iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
			iptables -I FORWARD -o ${SERVER_WG_NIC} -j ACCEPT
		EOF
		if [[ $CLIENT_IPV4 == "y" ]]; then
			echo "iptables -t nat -A POSTROUTING -s ${ipv4_network}/24 -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"$add_rules"
		fi
		if [[ $CLIENT_IPV6 == "y" ]]; then
			{
				echo "ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT"
				echo "ip6tables -I FORWARD -o ${SERVER_WG_NIC} -j ACCEPT"
				echo "ip6tables -t nat -A POSTROUTING -s ${ipv6_network}/64 -o ${SERVER_PUB_NIC} -j MASQUERADE"
			} >>"$add_rules"
		fi

		cat >"$rm_rules" <<-EOF
			#!/bin/sh
			iptables -D INPUT -i ${SERVER_PUB_NIC} -p udp --dport ${SERVER_PORT} -j ACCEPT 2>/dev/null || true
			iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT 2>/dev/null || true
			iptables -D FORWARD -o ${SERVER_WG_NIC} -j ACCEPT 2>/dev/null || true
		EOF
		if [[ $CLIENT_IPV4 == "y" ]]; then
			echo "iptables -t nat -D POSTROUTING -s ${ipv4_network}/24 -o ${SERVER_PUB_NIC} -j MASQUERADE 2>/dev/null || true" >>"$rm_rules"
		fi
		if [[ $CLIENT_IPV6 == "y" ]]; then
			{
				echo "ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT 2>/dev/null || true"
				echo "ip6tables -D FORWARD -o ${SERVER_WG_NIC} -j ACCEPT 2>/dev/null || true"
				echo "ip6tables -t nat -D POSTROUTING -s ${ipv6_network}/64 -o ${SERVER_PUB_NIC} -j MASQUERADE 2>/dev/null || true"
			} >>"$rm_rules"
		fi
		;;
	esac

	chmod +x "$add_rules" "$rm_rules"
}

installWireGuardPackages() {
	log_header "Installing WireGuard"

	if [[ $OS == "ubuntu" ]] || [[ $OS == "debian" && ${VERSION_ID%%.*} -gt 10 ]]; then
		run_cmd_fatal "Updating package lists" apt-get update
		run_cmd_fatal "Installing WireGuard" apt-get install -y wireguard iproute2 iptables procps qrencode curl ca-certificates
	elif [[ $OS == "debian" ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
		fi
		run_cmd_fatal "Updating package lists" apt-get update
		run_cmd_fatal "Installing dependencies" apt-get install -y iproute2 iptables procps qrencode curl ca-certificates
		run_cmd_fatal "Installing WireGuard from backports" apt-get install -y -t buster-backports wireguard
	elif [[ $OS == "fedora" ]]; then
		run_cmd_fatal "Installing WireGuard" dnf install -y wireguard-tools iproute iptables procps-ng qrencode curl ca-certificates
	elif [[ $OS == "centos" ]]; then
		if command -v dnf &>/dev/null; then
			if [[ ${VERSION_ID%%.*} -eq 8 ]]; then
				run_cmd_fatal "Installing repositories" dnf install -y epel-release elrepo-release
				run_cmd_fatal "Installing WireGuard kernel module" dnf install -y kmod-wireguard
			else
				run_cmd "Installing EPEL repository" dnf install -y epel-release
			fi
			run_cmd_fatal "Installing WireGuard" dnf install -y wireguard-tools iproute iptables procps-ng curl ca-certificates
			run_cmd_optional "Installing qrencode" dnf install -y qrencode
		else
			run_cmd_fatal "Installing repositories" yum install -y epel-release elrepo-release
			run_cmd_fatal "Installing WireGuard kernel module" yum install -y kmod-wireguard
			run_cmd_fatal "Installing WireGuard" yum install -y wireguard-tools iproute iptables procps-ng curl ca-certificates
			run_cmd_optional "Installing qrencode" yum install -y qrencode
		fi
	elif [[ $OS == "oracle" ]]; then
		if [[ ${VERSION_ID%%.*} -eq 8 ]]; then
			run_cmd_fatal "Installing Oracle developer repository" dnf install -y oraclelinux-developer-release-el8
			run_cmd "Disabling default developer repo" dnf config-manager --disable -y ol8_developer
			run_cmd "Enabling UEK repo" dnf config-manager --enable -y ol8_developer_UEKR6
			run_cmd "Restricting UEK packages" dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		fi
		run_cmd_fatal "Installing WireGuard" dnf install -y wireguard-tools iproute procps-ng iptables curl ca-certificates
		run_cmd_optional "Installing qrencode" dnf install -y qrencode
	elif [[ $OS == "amzn2023" ]]; then
		run_cmd_fatal "Installing WireGuard" dnf install -y wireguard-tools iproute iptables procps-ng qrencode curl ca-certificates
	elif [[ $OS == "opensuse" ]]; then
		run_cmd_fatal "Installing WireGuard" zypper install -y wireguard-tools iproute2 iptables procps qrencode curl ca-certificates
	elif [[ $OS == "arch" ]]; then
		if ! run_cmd "Installing WireGuard" pacman --needed --noconfirm -S wireguard-tools iproute2 iptables procps-ng qrencode; then
			log_fatal "Arch package installation failed. Update the system manually with 'pacman -Syu', reboot if the kernel changes, then run this script again."
		fi
	elif [[ $OS == "alpine" ]]; then
		run_cmd_fatal "Updating package lists" apk update
		run_cmd_fatal "Installing WireGuard" apk add wireguard-tools iproute2 iptables procps libqrencode-tools curl ca-certificates
	fi

	if ! command -v wg &>/dev/null; then
		log_fatal "WireGuard installation failed. The 'wg' command was not found."
	fi
}

buildAddressList() {
	local addresses=()
	[[ $CLIENT_IPV4 == "y" ]] && addresses+=("${SERVER_WG_IPV4}/24")
	[[ $CLIENT_IPV6 == "y" ]] && addresses+=("${SERVER_WG_IPV6}/64")
	(
		IFS=','
		echo "${addresses[*]}"
	)
}

installWireGuard() {
	if [[ ${NON_INTERACTIVE_INSTALL:-n} == "y" ]]; then
		set_installation_defaults
	else
		installQuestions
	fi

	validate_configuration
	checkArchPendingKernelUpgrade
	installWireGuardPackages

	run_cmd_fatal "Creating WireGuard directory" mkdir -p "$WG_DIR"
	chmod 700 "$WG_DIR"

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

	createFirewallScripts
	writeParams

	log_info "Generating server configuration..."
	{
		echo "[Interface]"
		echo "Address = $(buildAddressList)"
		echo "ListenPort = $SERVER_PORT"
		echo "PrivateKey = $SERVER_PRIV_KEY"
		[[ -n ${MTU:-} ]] && echo "MTU = $MTU"
		echo "PostUp = ${WG_DIR}/add-${SERVER_WG_NIC}-rules.sh"
		echo "PostDown = ${WG_DIR}/rm-${SERVER_WG_NIC}-rules.sh"
	} >"${WG_DIR}/${SERVER_WG_NIC}.conf"
	chmod 600 "${WG_DIR}/${SERVER_WG_NIC}.conf"

	log_info "Enabling IP forwarding..."
	run_cmd_fatal "Creating sysctl.d directory" mkdir -p /etc/sysctl.d
	{
		if [[ $CLIENT_IPV4 == "y" ]]; then
			echo "net.ipv4.ip_forward = 1"
		fi
		if [[ $CLIENT_IPV6 == "y" ]]; then
			echo "net.ipv6.conf.all.forwarding = 1"
		fi
	} >/etc/sysctl.d/99-wireguard.conf

	if [[ $OS == "fedora" ]]; then
		chmod -v 700 "$WG_DIR" >/dev/null
		chmod -v 600 "${WG_DIR}"/*.conf "$PARAMS_FILE" >/dev/null
		chmod -v 700 "${WG_DIR}"/*-rules.sh >/dev/null
	fi

	if [[ $OS == "alpine" ]]; then
		run_cmd "Applying sysctl rules" sysctl -p /etc/sysctl.d/99-wireguard.conf
		if command -v rc-update &>/dev/null && command -v rc-service &>/dev/null && [[ -d /etc/init.d ]]; then
			run_cmd "Enabling sysctl service" rc-update add sysctl
			run_cmd "Creating WireGuard OpenRC service" ln -sf /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			run_cmd "Starting WireGuard service" rc-service "wg-quick.${SERVER_WG_NIC}" start
			run_cmd "Enabling WireGuard service" rc-update add "wg-quick.${SERVER_WG_NIC}"
		else
			log_warn "OpenRC is not available. Start WireGuard manually with: wg-quick up ${SERVER_WG_NIC}"
		fi
	else
		run_cmd "Applying sysctl rules" sysctl --system
		if command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]; then
			run_cmd "Starting WireGuard service" systemctl start "wg-quick@${SERVER_WG_NIC}"
			run_cmd "Enabling WireGuard service" systemctl enable "wg-quick@${SERVER_WG_NIC}"
		else
			log_warn "systemctl is not available. Start WireGuard manually with: wg-quick up ${SERVER_WG_NIC}"
		fi
	fi

	if [[ ${NEW_CLIENT:-y} == "y" ]]; then
		newClient
		log_success "If you want to add more clients, you simply need to run this script another time."
	else
		log_info "No initial client was created. Run '$SCRIPT_NAME client add <name>' to add one."
	fi

	if isWireGuardRunning; then
		log_success "WireGuard is running."
		if [[ $OS == "alpine" ]]; then
			log_success "You can check the status with: rc-service wg-quick.${SERVER_WG_NIC} status"
		else
			log_success "You can check the status with: systemctl status wg-quick@${SERVER_WG_NIC}"
		fi
		log_warn "If you do not have internet connectivity from your client, try rebooting the server."
	else
		log_warn "WireGuard does not seem to be running."
		if [[ $OS == "alpine" ]]; then
			log_warn "Check with: rc-service wg-quick.${SERVER_WG_NIC} status"
		else
			log_warn "Check with: systemctl status wg-quick@${SERVER_WG_NIC}"
		fi
		log_warn "If you see 'Cannot find device ${SERVER_WG_NIC}', reboot the server."
	fi
}

isWireGuardRunning() {
	if [[ $OS == "alpine" ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status >/dev/null 2>&1
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" >/dev/null 2>&1
	fi
}

getHomeDirForClient() {
	local client_name="$1"

	if [[ -z $client_name ]]; then
		log_fatal "getHomeDirForClient() requires a client name."
	fi

	if [[ -d "/home/${client_name}" ]]; then
		echo "/home/${client_name}"
	elif [[ -n ${SUDO_USER:-} ]]; then
		if [[ $SUDO_USER == "root" ]]; then
			echo "/root"
		else
			echo "/home/${SUDO_USER}"
		fi
	else
		echo "/root"
	fi
}

getClientOwner() {
	local client_name="$1"
	if id "$client_name" &>/dev/null && [[ -d "/home/${client_name}" ]]; then
		echo "$client_name"
	elif [[ -n ${SUDO_USER:-} && $SUDO_USER != "root" ]]; then
		echo "$SUDO_USER"
	fi
}

setClientConfigPermissions() {
	local filepath="$1"
	local owner="$2"

	chmod go-rw "$filepath"
	if [[ -n $owner ]]; then
		local owner_group
		owner_group=$(id -gn "$owner")
		chown "$owner:$owner_group" "$filepath"
	fi
}

getClientConfigPath() {
	local client_name="$1"
	if [[ -n ${CLIENT_FILEPATH:-} ]]; then
		echo "$CLIENT_FILEPATH"
	else
		local home_dir
		home_dir=$(getHomeDirForClient "$client_name")
		echo "${home_dir}/${SERVER_WG_NIC}-client-${client_name}.conf"
	fi
}

normalizeEndpoint() {
	local endpoint="$SERVER_PUB_IP"
	if [[ $endpoint == *:* && $endpoint != \[* ]]; then
		endpoint="[${endpoint}]"
	fi
	echo "${endpoint}:${SERVER_PORT}"
}

clientExists() {
	local client_name="$1"
	grep -Fqx -- "### Client ${client_name}" "${WG_DIR}/${SERVER_WG_NIC}.conf"
}

ipExists() {
	local ip="$1"
	local cidr="$2"
	grep -Fq -- "${ip}/${cidr}" "${WG_DIR}/${SERVER_WG_NIC}.conf"
}

findNextClientIndex() {
	local idx candidate4 candidate6
	for idx in {2..254}; do
		candidate4="${SERVER_WG_IPV4%.*}.${idx}"
		candidate6="$(get_ipv6_network "$SERVER_WG_IPV6")${idx}"

		if [[ $CLIENT_IPV4 == "y" ]] && ipExists "$candidate4" 32; then
			continue
		fi
		if [[ $CLIENT_IPV6 == "y" ]] && ipExists "$candidate6" 128; then
			continue
		fi
		echo "$idx"
		return 0
	done
	return 1
}

buildClientAddressList() {
	local addresses=()
	[[ $CLIENT_IPV4 == "y" ]] && addresses+=("${CLIENT_WG_IPV4}/32")
	[[ $CLIENT_IPV6 == "y" ]] && addresses+=("${CLIENT_WG_IPV6}/128")
	(
		IFS=','
		echo "${addresses[*]}"
	)
}

buildDnsList() {
	if [[ -n $CLIENT_DNS_2 ]]; then
		echo "${CLIENT_DNS_1},${CLIENT_DNS_2}"
	else
		echo "$CLIENT_DNS_1"
	fi
}

newClient() {
	log_header "Client Configuration"

	if ! is_valid_client_name "${CLIENT_NAME:-}"; then
		log_prompt "The client name must consist of alphanumeric characters, underscores, or dashes and cannot exceed $MAX_CLIENT_NAME_LENGTH characters."
		until is_valid_client_name "${CLIENT_NAME:-}"; do
			read -rp "Client name: " -e CLIENT_NAME
		done
	else
		validate_client_name "$CLIENT_NAME"
	fi

	while clientExists "$CLIENT_NAME"; do
		if [[ ${NON_INTERACTIVE_INSTALL:-n} == "y" ]]; then
			log_fatal "A client named '$CLIENT_NAME' already exists."
		fi
		log_warn "A client with the specified name already exists. Please choose another name."
		CLIENT_NAME=""
		until is_valid_client_name "$CLIENT_NAME"; do
			read -rp "Client name: " -e CLIENT_NAME
		done
	done

	local client_index
	client_index=$(findNextClientIndex) || log_fatal "The configured subnet supports only 253 clients."

	if [[ $CLIENT_IPV4 == "y" ]]; then
		if [[ -z ${CLIENT_WG_IPV4:-} ]]; then
			CLIENT_WG_IPV4="${SERVER_WG_IPV4%.*}.${client_index}"
		fi
		if ! is_valid_ipv4 "$CLIENT_WG_IPV4"; then
			log_fatal "Invalid client WireGuard IPv4: $CLIENT_WG_IPV4"
		fi
		while ipExists "$CLIENT_WG_IPV4" 32; do
			if [[ ${NON_INTERACTIVE_INSTALL:-n} == "y" ]]; then
				log_fatal "Client IPv4 $CLIENT_WG_IPV4 already exists."
			fi
			log_warn "A client with the specified IPv4 already exists. Please choose another IPv4."
			read -rp "Client WireGuard IPv4: " -e -i "${SERVER_WG_IPV4%.*}.${client_index}" CLIENT_WG_IPV4
		done
	fi

	if [[ $CLIENT_IPV6 == "y" ]]; then
		if [[ -z ${CLIENT_WG_IPV6:-} ]]; then
			CLIENT_WG_IPV6="$(get_ipv6_network "$SERVER_WG_IPV6")${client_index}"
		fi
		if ! is_valid_ipv6 "$CLIENT_WG_IPV6"; then
			log_fatal "Invalid client WireGuard IPv6: $CLIENT_WG_IPV6"
		fi
		while ipExists "$CLIENT_WG_IPV6" 128; do
			if [[ ${NON_INTERACTIVE_INSTALL:-n} == "y" ]]; then
				log_fatal "Client IPv6 $CLIENT_WG_IPV6 already exists."
			fi
			log_warn "A client with the specified IPv6 already exists. Please choose another IPv6."
			read -rp "Client WireGuard IPv6: " -e -i "$(get_ipv6_network "$SERVER_WG_IPV6")${client_index}" CLIENT_WG_IPV6
		done
	fi

	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)
	ENDPOINT=$(normalizeEndpoint)

	local client_config_path parent_dir client_owner
	client_config_path=$(getClientConfigPath "$CLIENT_NAME")
	parent_dir=$(dirname "$client_config_path")
	run_cmd_fatal "Creating client config directory" mkdir -p "$parent_dir"

	{
		echo "[Interface]"
		echo "PrivateKey = $CLIENT_PRIV_KEY"
		echo "Address = $(buildClientAddressList)"
		echo "DNS = $(buildDnsList)"
		if [[ -n ${MTU:-} ]]; then
			echo "MTU = $MTU"
		else
			echo ""
			echo "# Uncomment the next line to set a custom MTU"
			echo "# This might impact performance, so use it only if you know what you are doing"
			echo "# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU"
			echo "# MTU = 1420"
		fi
		echo ""
		echo "[Peer]"
		echo "PublicKey = $SERVER_PUB_KEY"
		echo "PresharedKey = $CLIENT_PRE_SHARED_KEY"
		echo "Endpoint = $ENDPOINT"
		echo "AllowedIPs = $ALLOWED_IPS"
	} >"$client_config_path"

	client_owner=$(getClientOwner "$CLIENT_NAME")
	setClientConfigPermissions "$client_config_path" "$client_owner"

	{
		echo ""
		echo "### Client $CLIENT_NAME"
		echo "[Peer]"
		echo "PublicKey = $CLIENT_PUB_KEY"
		echo "PresharedKey = $CLIENT_PRE_SHARED_KEY"
		echo "AllowedIPs = $(buildClientAddressList)"
	} >>"${WG_DIR}/${SERVER_WG_NIC}.conf"

	if wg show "$SERVER_WG_NIC" &>/dev/null; then
		run_cmd "Applying WireGuard configuration" wg syncconf "$SERVER_WG_NIC" <(wg-quick strip "$SERVER_WG_NIC")
	else
		log_warn "WireGuard interface $SERVER_WG_NIC is not active; the new peer will apply when the interface starts."
	fi

	if command -v qrencode &>/dev/null && [[ $OUTPUT_FORMAT != "json" && -t 1 ]]; then
		log_success "Here is your client config file as a QR Code:"
		qrencode -t ansiutf8 -l L <"$client_config_path"
		echo ""
	fi

	log_success "Your client config file is in $client_config_path"
}

getClientNames() {
	grep -E "^### Client" "${WG_DIR}/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3
}

listClients() {
	local format="${OUTPUT_FORMAT:-table}"
	local clients=()
	local client

	while read -r client; do
		[[ -n $client ]] && clients+=("$client")
	done < <(getClientNames)

	if [[ ${#clients[@]} -eq 0 ]]; then
		if [[ $format == "json" ]]; then
			echo '{"clients":[]}'
		else
			log_warn "You have no existing clients."
		fi
		return 0
	fi

	if [[ $format == "json" ]]; then
		echo '{"clients":['
		local first=true
		for client in "${clients[@]}"; do
			[[ $first == true ]] && first=false || printf ','
			printf '{"name":"%s"}\n' "$(json_escape "$client")"
		done
		echo ']}'
	else
		log_header "WireGuard Clients"
		printf "   %-5s %s\n" "No." "Name"
		printf "   %-5s %s\n" "---" "----"
		local i=1
		for client in "${clients[@]}"; do
			printf "   %-5s %s\n" "${i})" "$client"
			((i++))
		done
	fi
}

selectClient() {
	local clients=()
	local client selected

	while read -r client; do
		[[ -n $client ]] && clients+=("$client")
	done < <(getClientNames)

	if [[ ${#clients[@]} -eq 0 ]]; then
		log_fatal "You have no existing clients."
	fi

	if [[ -n ${CLIENT_NAME:-} ]]; then
		for client in "${clients[@]}"; do
			if [[ $client == "$CLIENT_NAME" ]]; then
				return 0
			fi
		done
		log_fatal "Client '$CLIENT_NAME' was not found."
	fi

	log_prompt "Select the existing client you want to revoke"
	local i=1
	for client in "${clients[@]}"; do
		echo "   $i) $client"
		((i++))
	done

	until [[ $selected =~ ^[0-9]+$ ]] && ((selected >= 1 && selected <= ${#clients[@]})); do
		if [[ ${#clients[@]} -eq 1 ]]; then
			read -rp "Select one client [1]: " selected
		else
			read -rp "Select one client [1-${#clients[@]}]: " selected
		fi
	done
	CLIENT_NAME="${clients[$((selected - 1))]}"
}

revokeClient() {
	log_header "Revoke Client"
	selectClient

	if [[ ${REVOKE_CONFIRM:-n} != "y" ]]; then
		local confirm
		until [[ $confirm =~ ^[yn]$ ]]; do
			read -rp "Do you really want to revoke $CLIENT_NAME? [y/n]: " -e -i n confirm
		done
		if [[ $confirm != "y" ]]; then
			log_info "Revocation aborted."
			return 0
		fi
	fi

	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${WG_DIR}/${SERVER_WG_NIC}.conf"

	local default_path
	default_path="$(getHomeDirForClient "$CLIENT_NAME")/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	run_cmd "Removing default client config" rm -f "$default_path"
	run_cmd "Removing root client config" rm -f "/root/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
	run_cmd "Removing home client configs" find /home/ -maxdepth 2 -name "${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf" -delete

	if wg show "$SERVER_WG_NIC" &>/dev/null; then
		run_cmd "Applying WireGuard configuration" wg syncconf "$SERVER_WG_NIC" <(wg-quick strip "$SERVER_WG_NIC")
	fi

	log_success "Client $CLIENT_NAME revoked."
}

formatBytes() {
	local bytes="$1"
	if ! [[ $bytes =~ ^[0-9]+$ ]]; then
		echo "N/A"
	elif [[ $bytes -ge 1073741824 ]]; then
		awk "BEGIN {printf \"%.1fG\", $bytes/1073741824}"
	elif [[ $bytes -ge 1048576 ]]; then
		awk "BEGIN {printf \"%.1fM\", $bytes/1048576}"
	elif [[ $bytes -ge 1024 ]]; then
		awk "BEGIN {printf \"%.1fK\", $bytes/1024}"
	else
		echo "${bytes}B"
	fi
}

formatHandshake() {
	local epoch="$1"
	if [[ $epoch == "0" ]]; then
		echo "never"
		return
	fi
	local now delta
	now=$(date +%s)
	delta=$((now - epoch))
	if [[ $delta -lt 60 ]]; then
		echo "${delta}s ago"
	elif [[ $delta -lt 3600 ]]; then
		echo "$((delta / 60))m ago"
	elif [[ $delta -lt 86400 ]]; then
		echo "$((delta / 3600))h ago"
	else
		echo "$((delta / 86400))d ago"
	fi
}

listConnectedClients() {
	local format="${OUTPUT_FORMAT:-table}"

	if ! command -v wg &>/dev/null; then
		log_fatal "The 'wg' command was not found."
	fi
	if ! wg show "$SERVER_WG_NIC" &>/dev/null; then
		if [[ $format == "json" ]]; then
			echo '{"error":"WireGuard interface is not active","peers":[]}'
		else
			log_warn "WireGuard interface $SERVER_WG_NIC is not active."
		fi
		return 0
	fi

	local dump
	dump=$(wg show "$SERVER_WG_NIC" dump)
	if [[ $(echo "$dump" | wc -l) -le 1 ]]; then
		if [[ $format == "json" ]]; then
			echo '{"peers":[]}'
		else
			log_header "WireGuard Peers"
			log_info "No peers are configured."
		fi
		return 0
	fi

	if [[ $format == "json" ]]; then
		echo '{"peers":['
		local first=true
		tail -n +2 <<<"$dump" | while IFS=$'\t' read -r public_key preshared_key endpoint allowed_ips latest_handshake rx tx persistent_keepalive; do
			[[ $first == true ]] && first=false || printf ','
			printf '{"public_key":"%s","endpoint":"%s","allowed_ips":"%s","latest_handshake":%s,"transfer_rx":%s,"transfer_tx":%s,"persistent_keepalive":"%s"}\n' \
				"$(json_escape "$public_key")" "$(json_escape "$endpoint")" "$(json_escape "$allowed_ips")" \
				"${latest_handshake:-0}" "${rx:-0}" "${tx:-0}" "$(json_escape "$persistent_keepalive")"
		done
		echo ']}'
	else
		log_header "WireGuard Peers"
		printf "   %-44s %-22s %-18s %-16s %s\n" "Public Key" "Endpoint" "Allowed IPs" "Handshake" "Transfer"
		printf "   %-44s %-22s %-18s %-16s %s\n" "----------" "--------" "-----------" "---------" "--------"
		tail -n +2 <<<"$dump" | while IFS=$'\t' read -r public_key preshared_key endpoint allowed_ips latest_handshake rx tx persistent_keepalive; do
			local rx_human tx_human
			rx_human=$(formatBytes "${rx:-0}")
			tx_human=$(formatBytes "${tx:-0}")
			printf "   %-44s %-22s %-18s %-16s rx %s / tx %s\n" \
				"${public_key:0:43}" "${endpoint:-none}" "$allowed_ips" "$(formatHandshake "${latest_handshake:-0}")" "$rx_human" "$tx_human"
		done
	fi
}

uninstallWg() {
	log_header "Remove WireGuard"
	if [[ -z ${REMOVE:-} ]]; then
		log_warn "This will uninstall WireGuard and remove all configuration files."
		log_warn "Back up $WG_DIR first if you want to keep your configuration."
		read -rp "Do you really want to remove WireGuard? [y/n]: " -e -i n REMOVE
	fi

	if [[ $REMOVE != "y" ]]; then
		log_info "Removal aborted."
		return 0
	fi

	checkOS

	if [[ $OS == "alpine" ]]; then
		run_cmd "Stopping WireGuard service" rc-service "wg-quick.${SERVER_WG_NIC}" stop
		run_cmd "Disabling WireGuard service" rc-update del "wg-quick.${SERVER_WG_NIC}"
		run_cmd "Removing WireGuard service link" unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		run_cmd "Disabling sysctl service" rc-update del sysctl
	else
		run_cmd "Stopping WireGuard service" systemctl stop "wg-quick@${SERVER_WG_NIC}"
		run_cmd "Disabling WireGuard service" systemctl disable "wg-quick@${SERVER_WG_NIC}"
	fi

	if [[ -x ${WG_DIR}/rm-${SERVER_WG_NIC}-rules.sh ]]; then
		run_cmd "Removing firewall rules" "${WG_DIR}/rm-${SERVER_WG_NIC}-rules.sh"
	fi

	if [[ $OS == "ubuntu" || $OS == "debian" ]]; then
		run_cmd "Removing WireGuard" apt-get remove -y wireguard wireguard-tools qrencode
	elif [[ $OS == "fedora" ]]; then
		run_cmd "Removing WireGuard" dnf remove -y --noautoremove wireguard-tools qrencode
	elif [[ $OS == "centos" ]]; then
		if command -v dnf &>/dev/null; then
			run_cmd "Removing WireGuard" dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID%%.*} -eq 8 ]]; then
				run_cmd "Removing WireGuard kernel module" dnf remove -y --noautoremove kmod-wireguard
			fi
		else
			run_cmd "Removing WireGuard" yum remove -y --noautoremove wireguard-tools qrencode
			run_cmd "Removing WireGuard kernel module" yum remove -y --noautoremove kmod-wireguard
		fi
	elif [[ $OS == "oracle" || $OS == "amzn2023" ]]; then
		run_cmd "Removing WireGuard" dnf remove -y --noautoremove wireguard-tools qrencode
	elif [[ $OS == "opensuse" ]]; then
		run_cmd "Removing WireGuard" zypper remove -y wireguard-tools qrencode
	elif [[ $OS == "arch" ]]; then
		run_cmd "Removing WireGuard" pacman -Rs --noconfirm wireguard-tools qrencode
	elif [[ $OS == "alpine" ]]; then
		run_cmd "Removing WireGuard" apk del wireguard-tools libqrencode-tools
	fi

	run_cmd "Removing WireGuard configuration" rm -rf "$WG_DIR"
	run_cmd "Removing sysctl configuration" rm -f /etc/sysctl.d/99-wireguard.conf /etc/sysctl.d/wg.conf

	if [[ $OS != "alpine" ]]; then
		run_cmd "Reloading sysctl" sysctl --system
	fi

	log_success "WireGuard uninstalled successfully."
}

manageMenu() {
	local menu_option

	log_header "WireGuard Management"
	log_prompt "The git repository is available at: https://github.com/angristan/wireguard-install"
	log_success "WireGuard is already installed."
	log_menu ""
	log_prompt "What do you want to do?"
	log_menu "   1) Add a new user"
	log_menu "   2) List all users"
	log_menu "   3) Revoke existing user"
	log_menu "   4) Uninstall WireGuard"
	log_menu "   5) Show peer status"
	log_menu "   6) Exit"
	until [[ ${MENU_OPTION:-$menu_option} =~ ^[1-6]$ ]]; do
		read -rp "Select an option [1-6]: " menu_option
	done
	menu_option="${MENU_OPTION:-$menu_option}"

	case "$menu_option" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		listConnectedClients
		;;
	6)
		exit 0
		;;
	esac
}

cmd_install() {
	local interactive=false
	local no_client=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-i | --interactive)
			interactive=true
			shift
			;;
		--endpoint)
			[[ -z ${2:-} ]] && log_fatal "--endpoint requires an argument"
			SERVER_PUB_IP="$2"
			shift 2
			;;
		--public-interface)
			[[ -z ${2:-} ]] && log_fatal "--public-interface requires an argument"
			SERVER_PUB_NIC="$2"
			shift 2
			;;
		--wg-interface)
			[[ -z ${2:-} ]] && log_fatal "--wg-interface requires an argument"
			SERVER_WG_NIC="$2"
			shift 2
			;;
		--server-ipv4)
			[[ -z ${2:-} ]] && log_fatal "--server-ipv4 requires an argument"
			SERVER_WG_IPV4="$2"
			shift 2
			;;
		--server-ipv6)
			[[ -z ${2:-} ]] && log_fatal "--server-ipv6 requires an argument"
			SERVER_WG_IPV6="$2"
			shift 2
			;;
		--client-ipv4)
			CLIENT_IPV4=y
			shift
			;;
		--no-client-ipv4)
			CLIENT_IPV4=n
			shift
			;;
		--client-ipv6)
			CLIENT_IPV6=y
			shift
			;;
		--no-client-ipv6)
			CLIENT_IPV6=n
			shift
			;;
		--port)
			[[ -z ${2:-} ]] && log_fatal "--port requires an argument"
			validate_port "$2"
			SERVER_PORT="$2"
			shift 2
			;;
		--port-random)
			SERVER_PORT=random
			shift
			;;
		--dns-primary)
			[[ -z ${2:-} ]] && log_fatal "--dns-primary requires an argument"
			CLIENT_DNS_1="$2"
			shift 2
			;;
		--dns-secondary)
			[[ -z ${2:-} ]] && log_fatal "--dns-secondary requires an argument"
			CLIENT_DNS_2="$2"
			shift 2
			;;
		--allowed-ips)
			[[ -z ${2:-} ]] && log_fatal "--allowed-ips requires an argument"
			ALLOWED_IPS="$2"
			shift 2
			;;
		--mtu)
			[[ -z ${2:-} ]] && log_fatal "--mtu requires an argument"
			validate_mtu "$2"
			MTU="$2"
			shift 2
			;;
		--client)
			[[ -z ${2:-} ]] && log_fatal "--client requires an argument"
			validate_client_name "$2"
			CLIENT_NAME="$2"
			shift 2
			;;
		--output)
			[[ -z ${2:-} ]] && log_fatal "--output requires an argument"
			CLIENT_FILEPATH="$2"
			shift 2
			;;
		--no-client)
			no_client=true
			shift
			;;
		-h | --help)
			show_install_help
			exit 0
			;;
		*)
			log_fatal "Unknown option: $1. See '$SCRIPT_NAME install --help' for usage."
			;;
		esac
	done

	requireNoWireGuard

	if [[ $interactive == true ]]; then
		NON_INTERACTIVE_INSTALL=n
		installWireGuard
	else
		NON_INTERACTIVE_INSTALL=y
		APPROVE_INSTALL=y
		[[ $no_client == true ]] && NEW_CLIENT=n
		installWireGuard
	fi
}

cmd_uninstall() {
	local force=false
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_uninstall_help
			exit 0
			;;
		*)
			log_fatal "Unknown option: $1. See '$SCRIPT_NAME uninstall --help' for usage."
			;;
		esac
	done

	loadParams
	[[ $force == true ]] && REMOVE=y
	uninstallWg
}

cmd_client_add() {
	local client_name=""

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--ipv4)
			[[ -z ${2:-} ]] && log_fatal "--ipv4 requires an argument"
			CLIENT_WG_IPV4="$2"
			shift 2
			;;
		--ipv6)
			[[ -z ${2:-} ]] && log_fatal "--ipv6 requires an argument"
			CLIENT_WG_IPV6="$2"
			shift 2
			;;
		--output)
			[[ -z ${2:-} ]] && log_fatal "--output requires an argument"
			CLIENT_FILEPATH="$2"
			shift 2
			;;
		-h | --help)
			show_client_add_help
			exit 0
			;;
		-*)
			log_fatal "Unknown option: $1. See '$SCRIPT_NAME client add --help' for usage."
			;;
		*)
			if [[ -z $client_name ]]; then
				client_name="$1"
			else
				log_fatal "Unexpected argument: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z $client_name ]] && log_fatal "Client name is required. See '$SCRIPT_NAME client add --help' for usage."
	validate_client_name "$client_name"
	loadParams
	CLIENT_NAME="$client_name"
	NON_INTERACTIVE_INSTALL=y
	newClient
}

cmd_client_list() {
	local format="table"
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--format)
			[[ -z ${2:-} ]] && log_fatal "--format requires an argument"
			case "$2" in
			table | json) format="$2" ;;
			*) log_fatal "Invalid format: $2. Use 'table' or 'json'." ;;
			esac
			shift 2
			;;
		-h | --help)
			show_client_list_help
			exit 0
			;;
		*)
			log_fatal "Unknown option: $1. See '$SCRIPT_NAME client list --help' for usage."
			;;
		esac
	done

	loadParams
	OUTPUT_FORMAT="$format"
	listClients
}

cmd_client_revoke() {
	local client_name=""
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_client_revoke_help
			exit 0
			;;
		-*)
			log_fatal "Unknown option: $1. See '$SCRIPT_NAME client revoke --help' for usage."
			;;
		*)
			if [[ -z $client_name ]]; then
				client_name="$1"
			else
				log_fatal "Unexpected argument: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z $client_name ]] && log_fatal "Client name is required. See '$SCRIPT_NAME client revoke --help' for usage."
	validate_client_name "$client_name"
	loadParams
	CLIENT_NAME="$client_name"
	[[ $force == true ]] && REVOKE_CONFIRM=y
	NON_INTERACTIVE_INSTALL=y
	revokeClient
}

cmd_client() {
	local subcmd="${1:-}"
	shift || true

	case "$subcmd" in
	"" | -h | --help)
		show_client_help
		exit 0
		;;
	add)
		cmd_client_add "$@"
		;;
	list)
		cmd_client_list "$@"
		;;
	revoke)
		cmd_client_revoke "$@"
		;;
	*)
		log_fatal "Unknown client subcommand: $subcmd. See '$SCRIPT_NAME client --help' for usage."
		;;
	esac
}

cmd_server_status() {
	local format="table"
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--format)
			[[ -z ${2:-} ]] && log_fatal "--format requires an argument"
			case "$2" in
			table | json) format="$2" ;;
			*) log_fatal "Invalid format: $2. Use 'table' or 'json'." ;;
			esac
			shift 2
			;;
		-h | --help)
			show_server_status_help
			exit 0
			;;
		*)
			log_fatal "Unknown option: $1. See '$SCRIPT_NAME server status --help' for usage."
			;;
		esac
	done

	loadParams
	OUTPUT_FORMAT="$format"
	listConnectedClients
}

cmd_server() {
	local subcmd="${1:-}"
	shift || true

	case "$subcmd" in
	"" | -h | --help)
		show_server_help
		exit 0
		;;
	status)
		cmd_server_status "$@"
		;;
	*)
		log_fatal "Unknown server subcommand: $subcmd. See '$SCRIPT_NAME server --help' for usage."
		;;
	esac
}

cmd_interactive() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			echo "Launch interactive menu for WireGuard management"
			echo ""
			echo "Usage: $SCRIPT_NAME interactive"
			exit 0
			;;
		*)
			log_fatal "Unknown option: $1"
			;;
		esac
	done

	if isWireGuardInstalled; then
		loadParams
		manageMenu
	else
		installWireGuard
	fi
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--verbose)
			VERBOSE=1
			shift
			;;
		--log)
			[[ -z ${2:-} ]] && log_fatal "--log requires an argument"
			LOG_FILE="$2"
			shift 2
			;;
		--no-log)
			LOG_FILE=""
			shift
			;;
		--no-color)
			COLOR_RESET=''
			COLOR_RED=''
			COLOR_GREEN=''
			COLOR_YELLOW=''
			COLOR_BLUE=''
			COLOR_CYAN=''
			COLOR_DIM=''
			COLOR_BOLD=''
			shift
			;;
		-h | --help)
			show_help
			exit 0
			;;
		-*)
			break
			;;
		*)
			break
			;;
		esac
	done

	local cmd="${1:-}"
	shift || true

	local wants_help=false
	local prev_arg=""
	for arg in "$@"; do
		if [[ $arg == "-h" || $arg == "--help" ]]; then
			wants_help=true
		fi
		if [[ $prev_arg == "--format" && $arg == "json" ]]; then
			OUTPUT_FORMAT=json
		fi
		prev_arg="$arg"
	done

	case "$cmd" in
	"")
		show_help
		exit 0
		;;
	install)
		[[ $wants_help == false ]] && initialCheck
		cmd_install "$@"
		;;
	uninstall)
		[[ $wants_help == false ]] && initialCheck
		cmd_uninstall "$@"
		;;
	client)
		[[ $wants_help == false ]] && initialCheck
		cmd_client "$@"
		;;
	server)
		[[ $wants_help == false ]] && initialCheck
		cmd_server "$@"
		;;
	interactive)
		[[ $wants_help == false ]] && initialCheck
		cmd_interactive "$@"
		;;
	*)
		log_fatal "Unknown command: $cmd. See '$SCRIPT_NAME --help' for usage."
		;;
	esac
}

main() {
	if [[ $# -gt 0 ]]; then
		parse_args "$@"
		return
	fi

	initialCheck
	if isWireGuardInstalled; then
		loadParams
		manageMenu
	else
		if [[ ${AUTO_INSTALL:-n} == "y" || ${NON_INTERACTIVE_INSTALL:-n} == "y" ]]; then
			NON_INTERACTIVE_INSTALL=y
			APPROVE_INSTALL=y
		fi
		installWireGuard
	fi
}

main "$@"
