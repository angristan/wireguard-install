#!/bin/bash

# Secure WireGuard server installer with IP version option and multi-server support
# Modified from https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function installPackages() {
	if ! "$@"; then
		echo -e "${RED}Failed to install packages.${NC}"
		echo "Please check your internet connection and package sources."
		exit 1
	fi
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if command -v virt-what &>/dev/null; then
		VIRT=$(virt-what)
	else
		VIRT=$(systemd-detect-virt)
	fi
	if [[ ${VIRT} == "openvz" ]]; then
		echo "OpenVZ is not supported"
		exit 1
	fi
	if [[ ${VIRT} == "lxc" ]]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			if ! (apk update && apk add virt-what); then
				echo -e "${RED}Failed to install virt-what. Continuing without virtualization check.${NC}"
			fi
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

# Returns the interface name of every server profile, one per line.
function listProfiles() {
	local f
	for f in /etc/wireguard/params-*; do
		[[ -e "$f" ]] || continue
		printf '%s\n' "${f#/etc/wireguard/params-}"
	done
}

# Load a profile's variables into the current shell.
function loadProfile() {
	local iface=$1
	if [[ ! -e "/etc/wireguard/params-${iface}" ]]; then
		echo -e "${RED}Profile ${iface} not found.${NC}"
		return 1
	fi
	source "/etc/wireguard/params-${iface}"
}

# Read a single key from a params file (helper for conflict checks).
function readProfileKey() {
	local file=$1
	local key=$2
	grep -E "^${key}=" "$file" 2>/dev/null | head -n1 | cut -d= -f2-
}

# Silently migrate a pre-multi-profile install to the new per-profile layout.
function migrateLegacyParams() {
	if [[ -e /etc/wireguard/params && ! -L /etc/wireguard/params ]]; then
		local iface
		iface=$(readProfileKey /etc/wireguard/params SERVER_WG_NIC)
		if [[ -n "$iface" && ! -e "/etc/wireguard/params-${iface}" ]]; then
			mv /etc/wireguard/params "/etc/wireguard/params-${iface}"
		fi
	fi
}

# True if the interface name is already used by an existing profile.
function isInterfaceTaken() {
	local iface=$1
	[[ -e "/etc/wireguard/params-${iface}" ]] || [[ -e "/etc/wireguard/${iface}.conf" ]]
}

# True if any other profile already listens on this UDP port.
function isPortTaken() {
	local port=$1
	local skip=$2
	local f existing_iface existing_port
	for f in /etc/wireguard/params-*; do
		[[ -e "$f" ]] || continue
		existing_iface=${f#/etc/wireguard/params-}
		[[ "$existing_iface" == "$skip" ]] && continue
		existing_port=$(readProfileKey "$f" SERVER_PORT)
		if [[ "$existing_port" == "$port" ]]; then
			return 0
		fi
	done
	return 1
}

# True if any other profile already uses this IPv4 /24 subnet.
function isIPv4SubnetTaken() {
	local ipv4=$1
	local skip=$2
	local subnet
	subnet=$(echo "$ipv4" | awk -F. '{print $1"."$2"."$3}')
	local f existing_iface existing_ipv4 existing_subnet
	for f in /etc/wireguard/params-*; do
		[[ -e "$f" ]] || continue
		existing_iface=${f#/etc/wireguard/params-}
		[[ "$existing_iface" == "$skip" ]] && continue
		existing_ipv4=$(readProfileKey "$f" SERVER_WG_IPV4)
		existing_subnet=$(echo "$existing_ipv4" | awk -F. '{print $1"."$2"."$3}')
		if [[ "$existing_subnet" == "$subnet" ]]; then
			return 0
		fi
	done
	return 1
}

# True if any other profile already uses this IPv6 /64 prefix.
function isIPv6SubnetTaken() {
	local ipv6=$1
	local skip=$2
	local prefix
	prefix=$(echo "$ipv6" | awk -F'::' '{print $1}')
	local f existing_iface existing_ipv6 existing_prefix
	for f in /etc/wireguard/params-*; do
		[[ -e "$f" ]] || continue
		existing_iface=${f#/etc/wireguard/params-}
		[[ "$existing_iface" == "$skip" ]] && continue
		existing_ipv6=$(readProfileKey "$f" SERVER_WG_IPV6)
		existing_prefix=$(echo "$existing_ipv6" | awk -F'::' '{print $1}')
		if [[ "$existing_prefix" == "$prefix" ]]; then
			return 0
		fi
	done
	return 1
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The main git repository is available at: https://github.com/angristan/wireguard-install"
	echo "This repository is a modified version with IP version choice and multi-server support."
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Ask for IP protocol version
	echo "Which IP protocol version would you like to use?"
	echo "   1) IPv4 only"
	echo "   2) IPv6 only"
	echo "   3) Both IPv4 and IPv6 (dual stack)"
	until [[ ${IP_VERSION} =~ ^[1-3]$ ]]; do
		read -rp "Select an option [1-3]: " -e -i 3 IP_VERSION
	done

	# Detect public IPv4 or IPv6 address based on selected option
	if [[ ${IP_VERSION} == 1 ]] || [[ ${IP_VERSION} == 3 ]]; then
		SERVER_PUB_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
		read -rp "IPv4 public address: " -e -i "${SERVER_PUB_IPV4}" SERVER_PUB_IPV4
		SERVER_PUB_IP=${SERVER_PUB_IPV4}
	fi

	if [[ ${IP_VERSION} == 2 ]] || [[ ${IP_VERSION} == 3 ]]; then
		SERVER_PUB_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		read -rp "IPv6 public address: " -e -i "${SERVER_PUB_IPV6}" SERVER_PUB_IPV6

		# If IPv6 only, set SERVER_PUB_IP to the IPv6 address
		if [[ ${IP_VERSION} == 2 ]]; then
			SERVER_PUB_IP=${SERVER_PUB_IPV6}
		fi
	fi

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	# WireGuard interface name — must not collide with an existing profile
	SERVER_WG_NIC=""
	while true; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
		if [[ ! ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ ]] || [[ ${#SERVER_WG_NIC} -ge 16 ]]; then
			echo -e "${ORANGE}Invalid interface name. Use alphanumerics/underscore, max 15 chars.${NC}"
			SERVER_WG_NIC=""
			continue
		fi
		if isInterfaceTaken "${SERVER_WG_NIC}"; then
			echo -e "${ORANGE}Interface '${SERVER_WG_NIC}' is already in use by another profile. Choose a different name.${NC}"
			SERVER_WG_NIC=""
			continue
		fi
		break
	done

	# WireGuard IPv4 settings — must not collide with an existing /24
	if [[ ${IP_VERSION} == 1 ]] || [[ ${IP_VERSION} == 3 ]]; then
		SERVER_WG_IPV4=""
		while true; do
			read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
			if [[ ! ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; then
				echo -e "${ORANGE}Invalid IPv4 address.${NC}"
				SERVER_WG_IPV4=""
				continue
			fi
			if isIPv4SubnetTaken "${SERVER_WG_IPV4}" "${SERVER_WG_NIC}"; then
				echo -e "${ORANGE}The /24 subnet for ${SERVER_WG_IPV4} overlaps an existing profile. Pick a different subnet.${NC}"
				SERVER_WG_IPV4=""
				continue
			fi
			break
		done
	else
		# If IPv6 only, set a dummy value for the variables we need
		SERVER_WG_IPV4="10.66.66.1"
	fi

	# WireGuard IPv6 settings — must not collide with an existing /64
	if [[ ${IP_VERSION} == 2 ]] || [[ ${IP_VERSION} == 3 ]]; then
		SERVER_WG_IPV6=""
		while true; do
			read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
			if [[ ! ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; then
				echo -e "${ORANGE}Invalid IPv6 address.${NC}"
				SERVER_WG_IPV6=""
				continue
			fi
			if isIPv6SubnetTaken "${SERVER_WG_IPV6}" "${SERVER_WG_NIC}"; then
				echo -e "${ORANGE}The /64 prefix for ${SERVER_WG_IPV6} overlaps an existing profile. Pick a different prefix.${NC}"
				SERVER_WG_IPV6=""
				continue
			fi
			break
		done
	else
		# If IPv4 only, set a dummy value for the variables we need
		SERVER_WG_IPV6="fd42:42:42::1"
	fi

	# Generate random number within private ports range — must not collide with another profile
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	while isPortTaken "${RANDOM_PORT}" ""; do
		RANDOM_PORT=$(shuf -i49152-65535 -n1)
	done
	SERVER_PORT=""
	while true; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
		if [[ ! ${SERVER_PORT} =~ ^[0-9]+$ ]] || [ "${SERVER_PORT}" -lt 1 ] || [ "${SERVER_PORT}" -gt 65535 ]; then
			echo -e "${ORANGE}Invalid port number.${NC}"
			SERVER_PORT=""
			continue
		fi
		if isPortTaken "${SERVER_PORT}" "${SERVER_WG_NIC}"; then
			echo -e "${ORANGE}Port ${SERVER_PORT} is already used by another profile.${NC}"
			SERVER_PORT=""
			continue
		fi
		break
	done

	# Cloudflare DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	# Determine default for AllowedIPs based on IP version choice
	if [[ ${IP_VERSION} == 1 ]]; then
		DEFAULT_ALLOWED_IPS="0.0.0.0/0"
	elif [[ ${IP_VERSION} == 2 ]]; then
		DEFAULT_ALLOWED_IPS="::/0"
	else # Both IPv4 & IPv6
		DEFAULT_ALLOWED_IPS="0.0.0.0/0,::/0"
	fi

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i "${DEFAULT_ALLOWED_IPS}" ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="${DEFAULT_ALLOWED_IPS}"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

# Recompute /etc/sysctl.d/wg.conf from the union of every profile's IP_VERSION.
function writeSysctlForwarding() {
	local need_v4=0 need_v6=0 iv f
	for f in /etc/wireguard/params-*; do
		[[ -e "$f" ]] || continue
		iv=$(readProfileKey "$f" IP_VERSION)
		[[ "$iv" == "1" || "$iv" == "3" ]] && need_v4=1
		[[ "$iv" == "2" || "$iv" == "3" ]] && need_v6=1
	done
	{
		[[ $need_v4 -eq 1 ]] && echo "net.ipv4.ip_forward = 1"
		[[ $need_v6 -eq 1 ]] && echo "net.ipv6.conf.all.forwarding = 1"
	} >/etc/sysctl.d/wg.conf
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard packages only if not already present (additional profiles reuse them)
	if ! command -v wg &>/dev/null; then
		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
			apt-get update
			installPackages apt-get install -y wireguard iptables resolvconf qrencode
		elif [[ ${OS} == 'debian' ]]; then
			if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
				echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
				apt-get update
			fi
			apt-get update
			installPackages apt-get install -y iptables resolvconf qrencode
			installPackages apt-get install -y -t buster-backports wireguard
		elif [[ ${OS} == 'fedora' ]]; then
			if [[ ${VERSION_ID} -lt 32 ]]; then
				installPackages dnf install -y dnf-plugins-core
				dnf copr enable -y jdoss/wireguard
				installPackages dnf install -y wireguard-dkms
			fi
			installPackages dnf install -y wireguard-tools iptables qrencode
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			if [[ ${VERSION_ID} == 8* ]]; then
				installPackages yum install -y epel-release elrepo-release
				installPackages yum install -y kmod-wireguard
				yum install -y qrencode || true # not available on release 9
			fi
			installPackages yum install -y wireguard-tools iptables
		elif [[ ${OS} == 'oracle' ]]; then
			installPackages dnf install -y oraclelinux-developer-release-el8
			dnf config-manager --disable -y ol8_developer
			dnf config-manager --enable -y ol8_developer_UEKR6
			dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
			installPackages dnf install -y wireguard-tools qrencode iptables
		elif [[ ${OS} == 'arch' ]]; then
			installPackages pacman -S --needed --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			apk update
			installPackages apk add wireguard-tools iptables libqrencode-tools
		fi

		# Verify WireGuard installation
		if ! command -v wg &>/dev/null; then
			echo -e "${RED}WireGuard installation failed. The 'wg' command was not found.${NC}"
			echo "Please check the installation output above for errors."
			exit 1
		fi
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings to a per-profile params file
	echo "IP_VERSION=${IP_VERSION}
SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_IPV4=${SERVER_PUB_IPV4}
SERVER_PUB_IPV6=${SERVER_PUB_IPV6}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >"/etc/wireguard/params-${SERVER_WG_NIC}"

	# Configure server interface based on IP version
	if [[ ${IP_VERSION} == 1 ]]; then
		# IPv4 only
		echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	elif [[ ${IP_VERSION} == 2 ]]; then
		# IPv6 only
		echo "[Interface]
Address = ${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		# Dual stack (both IPv4 & IPv6)
		echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Add firewall rules based on IP version
	if pgrep firewalld; then
		# Using firewalld
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')

		if [[ ${IP_VERSION} == 1 ]]; then
			# IPv4 only
			echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		elif [[ ${IP_VERSION} == 2 ]]; then
			# IPv6 only
			echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		else
			# Dual stack
			echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		fi
	else
		# Using iptables
		if [[ ${IP_VERSION} == 1 ]]; then
			# IPv4 only
			echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		elif [[ ${IP_VERSION} == 2 ]]; then
			# IPv6 only
			echo "PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		else
			# Dual stack
			echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		fi
	fi

	# Enable IP forwarding from the union of every profile's IP_VERSION
	writeSysctlForwarding

	if [[ ${OS} == 'fedora' ]]; then
		chmod -v 700 /etc/wireguard
		chmod -v 600 /etc/wireguard/*
	fi

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	newClient
	echo -e "${GREEN}If you want to add more clients or another server instance, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration for profile '${SERVER_WG_NIC}'"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
		fi
	done

	# Set up IPv4 for the client if IPv4 is enabled
	if [[ ${IP_VERSION} == 1 ]] || [[ ${IP_VERSION} == 3 ]]; then
		for DOT_IP in {2..254}; do
			DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
			if [[ ${DOT_EXISTS} == '0' ]]; then
				break
			fi
		done

		if [[ ${DOT_EXISTS} == '1' ]]; then
			echo ""
			echo "The subnet configured supports only 253 clients."
			exit 1
		fi

		BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
		until [[ ${IPV4_EXISTS} == '0' ]]; do
			read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
			CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
			IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

			if [[ ${IPV4_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
				echo ""
			fi
		done
	fi

	# Set up IPv6 for the client if IPv6 is enabled
	if [[ ${IP_VERSION} == 2 ]] || [[ ${IP_VERSION} == 3 ]]; then
		BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
		until [[ ${IPV6_EXISTS} == '0' ]]; do
			read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
			CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
			IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

			if [[ ${IPV6_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
				echo ""
			fi
		done
	fi

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file based on IP version
	if [[ ${IP_VERSION} == 1 ]]; then
		# IPv4 only
		echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

		# Add the client as a peer to the server
		echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	elif [[ ${IP_VERSION} == 2 ]]; then
		# IPv6 only
		echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

		# Add the client as a peer to the server
		echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	else
		# Dual stack
		echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

# Uncomment the next line to set a custom MTU
# This might impact performance, so use it only if you know what you are doing
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

		# Add the client as a peer to the server
		echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

# Remove every package and host config installed by this script. Used by both
# the explicit "Uninstall ALL" path and the last-profile path inside uninstallWg.
function removeWireGuardPackages() {
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
		apt-get remove -y wireguard wireguard-tools qrencode
	elif [[ ${OS} == 'fedora' ]]; then
		dnf remove -y --noautoremove wireguard-tools qrencode
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf remove -y --noautoremove wireguard-dkms
			dnf copr disable -y jdoss/wireguard
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		yum remove -y --noautoremove wireguard-tools
		if [[ ${VERSION_ID} == 8* ]]; then
			yum remove --noautoremove kmod-wireguard qrencode
		fi
	elif [[ ${OS} == 'oracle' ]]; then
		yum remove --noautoremove wireguard-tools qrencode
	elif [[ ${OS} == 'arch' ]]; then
		pacman -Rs --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		(cd qrencode-4.1.1 || exit && make uninstall)
		rm -rf qrencode-* || exit
		apk del wireguard-tools libqrencode libqrencode-tools
	fi

	rm -rf /etc/wireguard
	rm -f /etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		rc-update del sysctl 2>/dev/null || true
	else
		sysctl --system
	fi
}

# Uninstall a single profile. If it's the last one, also remove packages.
function uninstallWg() {
	local remaining
	remaining=$(listProfiles | wc -l)
	local is_last=false
	[[ ${remaining} -le 1 ]] && is_last=true

	echo ""
	echo -e "${RED}WARNING: This will uninstall the WireGuard profile '${SERVER_WG_NIC}'.${NC}"
	if [[ ${is_last} == true ]]; then
		echo -e "${ORANGE}This is the last profile — packages and /etc/wireguard will also be removed.${NC}"
	fi
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove this profile? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE != 'y' ]]; then
		echo ""
		echo "Removal aborted!"
		return
	fi

	checkOS

	# Stop and disable just this profile's service
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" stop 2>/dev/null || true
		rc-update del "wg-quick.${SERVER_WG_NIC}" 2>/dev/null || true
		unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}" 2>/dev/null || true
	else
		systemctl stop "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
		systemctl disable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
	fi

	# Remove this profile's files
	rm -f "/etc/wireguard/${SERVER_WG_NIC}.conf"
	rm -f "/etc/wireguard/params-${SERVER_WG_NIC}"

	if [[ ${is_last} == true ]]; then
		removeWireGuardPackages
		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?
		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		fi
		echo "WireGuard uninstalled successfully."
		exit 0
	else
		# Refresh sysctl flags based on the surviving profiles
		writeSysctlForwarding
		[[ ${OS} != 'alpine' ]] && sysctl --system >/dev/null
		echo "Profile '${SERVER_WG_NIC}' removed. $((remaining - 1)) profile(s) remaining."
		exit 0
	fi
}

# Remove every profile and the WireGuard install in one shot.
function uninstallAllWg() {
	echo ""
	echo -e "${RED}WARNING: This will uninstall ALL WireGuard profiles and remove WireGuard packages from this host.${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove ALL WireGuard installations? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE != 'y' ]]; then
		echo ""
		echo "Removal aborted!"
		return
	fi

	checkOS

	local iface
	while IFS= read -r iface; do
		[[ -n "$iface" ]] || continue
		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${iface}" stop 2>/dev/null || true
			rc-update del "wg-quick.${iface}" 2>/dev/null || true
			unlink "/etc/init.d/wg-quick.${iface}" 2>/dev/null || true
		else
			systemctl stop "wg-quick@${iface}" 2>/dev/null || true
			systemctl disable "wg-quick@${iface}" 2>/dev/null || true
		fi
	done < <(listProfiles)

	removeWireGuardPackages

	echo "All WireGuard profiles uninstalled successfully."
	exit 0
}

# Sub-menu shown after the user has selected a profile.
function profileMenu() {
	echo ""
	echo "Profile: ${SERVER_WG_NIC}  (port ${SERVER_PORT}, IPv4 ${SERVER_WG_IPV4})"
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall this profile"
	echo "   5) Exit"
	local MENU_OPTION=""
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1) newClient ;;
	2) listClients ;;
	3) revokeClient ;;
	4) uninstallWg ;;
	5) exit 0 ;;
	esac
}

# Top-level menu: pick a profile (or install a new server / uninstall all / exit).
function manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""

	local profiles=()
	local p
	while IFS= read -r p; do
		[[ -n "$p" ]] && profiles+=("$p")
	done < <(listProfiles)

	echo "Existing WireGuard server profiles:"
	local idx=1
	local profile_port profile_ipv4
	for p in "${profiles[@]}"; do
		profile_port=$(readProfileKey "/etc/wireguard/params-${p}" SERVER_PORT)
		profile_ipv4=$(readProfileKey "/etc/wireguard/params-${p}" SERVER_WG_IPV4)
		echo "   ${idx}) ${p}  (port ${profile_port}, IPv4 ${profile_ipv4})"
		idx=$((idx + 1))
	done
	local install_opt=$((${#profiles[@]} + 1))
	local uninstall_all_opt=$((${#profiles[@]} + 2))
	local exit_opt=$((${#profiles[@]} + 3))
	echo "   ${install_opt}) Install a new WireGuard server instance"
	echo "   ${uninstall_all_opt}) Uninstall ALL WireGuard profiles"
	echo "   ${exit_opt}) Exit"

	local CHOICE=""
	until [[ ${CHOICE} =~ ^[0-9]+$ && ${CHOICE} -ge 1 && ${CHOICE} -le ${exit_opt} ]]; do
		read -rp "Select an option [1-${exit_opt}]: " CHOICE
	done

	if [[ ${CHOICE} -eq ${install_opt} ]]; then
		installWireGuard
		return
	fi
	if [[ ${CHOICE} -eq ${uninstall_all_opt} ]]; then
		uninstallAllWg
		return
	fi
	if [[ ${CHOICE} -eq ${exit_opt} ]]; then
		exit 0
	fi

	# Otherwise: selected an existing profile
	local selected=${profiles[$((CHOICE - 1))]}
	loadProfile "${selected}" || exit 1
	profileMenu
}

# Check for root, virt, OS...
initialCheck

# Move any legacy single-profile params file into the per-profile layout.
migrateLegacyParams

# Route to manage menu if any profile exists; otherwise run a fresh install.
if compgen -G "/etc/wireguard/params-*" >/dev/null; then
	manageMenu
else
	installWireGuard
fi
