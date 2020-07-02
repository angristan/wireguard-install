#!/bin/bash

# Secure WireGuard server installer for Debian, Ubuntu, CentOS, Fedora and Arch Linux
# https://github.com/angristan/wireguard-install

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	# Check OS version
	if [[ -e /etc/debian_version ]]; then
		# shellcheck disable=SC1091
		source /etc/os-release
		OS="${ID}" # debian or ubuntu
	elif [[ -e /etc/fedora-release ]]; then
		# shellcheck disable=SC1091
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		OS=centos
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z "${SERVER_PUB_IP}" ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ "${SERVER_PUB_NIC}" =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ "${SERVER_WG_NIC}" =~ ^[a-zA-Z0-9_]+$ ]]; do
		# shellcheck disable=SC2034
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ "${SERVER_WG_IPV4}" =~ ^([0-9]{1,3}\.){3}1$ ]]; do
		read -rp "Server's WireGuard IPv4 [x.x.x.1]: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ "${SERVER_WG_IPV6}" =~ ^([a-f0-9]{1,4}:){3,4}:1$ ]]; do
		read -rp "Server's WireGuard IPv6 [x:x:x::1]: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ "${SERVER_PORT}" =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server's WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ "${CLIENT_DNS_1}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the client: " -e -i 176.103.130.130 CLIENT_DNS_1
	done
	until [[ "${CLIENT_DNS_2}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the client (optional): " -e -i 176.103.130.131 CLIENT_DNS_2
		if [[ "${CLIENT_DNS_2}" == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	if [[ "${OS}" == 'ubuntu' ]]; then
		apt-get install -y software-properties-common
		add-apt-repository -y ppa:wireguard/wireguard
		apt-get update
		apt-get install -y "linux-headers-$(uname -r)"
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ "${OS}" == 'debian' ]]; then
		echo "deb http://deb.debian.org/debian/ unstable main" >/etc/apt/sources.list.d/unstable.list
		printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' >/etc/apt/preferences.d/limit-unstable
		apt update
		apt-get install -y "linux-headers-$(uname -r)"
		apt-get install -y wireguard iptables resolvconf qrencode
		apt-get install -y bc # mitigate https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=956869
	elif [[ "${OS}" == 'fedora' ]]; then
		if [[ "${VERSION_ID}" -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ "${OS}" == 'centos' ]]; then
		curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
		yum -y install epel-release
		yum -y install wireguard-dkms wireguard-tools iptables qrencode
	elif [[ "${OS}" == 'arch' ]]; then
		pacman -S --noconfirm linux-headers
		pacman -S --noconfirm wireguard-tools iptables qrencode
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if [ -x "$(command -v firewall-cmd)" ]; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		# shellcheck disable=SC2001
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# Warn user about kernel version mismatch with headers
	if [[ "${OS}" =~ (fedora|centos) ]] && [[ "${WG_RUNNING}" -ne 0 ]]; then
		echo -e "\nWARNING: WireGuard does not seem to be running."
		echo "Due to kernel mismatch issues on ${OS}, WireGuard might work if your system is out of date."
		echo "You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}"
		echo 'If you get something like "Cannot find device wg0", please run:'
		if [[ "${OS}" == 'fedora' ]]; then
			echo "dnf update -y && reboot"
		elif [[ "${OS}" == 'centos' ]]; then
			echo "yum update -y && reboot"
		fi
	fi

	newClient
	echo "If you want to add more clients, you simply need to run this script another time!"
}

function newClient() {
	# Load params
	# shellcheck disable=SC1091
	source /etc/wireguard/params

	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	printf "\n"
	until [[ "${CLIENT_WG_IPV4}" =~ ^([0-9]{1,3}\.?){4}$ ]]; do
		read -rp "Client's WireGuard IPv4: " -e -i "${SERVER_WG_IPV4::-1}"2 CLIENT_WG_IPV4
	done

	until [[ "${CLIENT_WG_IPV6}" =~ ^([a-f0-9]{1,4}:?:?){3,5} ]]; do
		read -rp "Client's WireGuard IPv6 : " -e -i "${SERVER_WG_IPV6::-1}"2 CLIENT_WG_IPV6
	done

	CLIENT_NAME=$(
		head /dev/urandom | tr -dc A-Za-z0-9 | head -c 10
		echo ''
	)

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/24,${CLIENT_WG_IPV6}/64
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0,::/0" >>"${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	systemctl restart "wg-quick@${SERVER_WG_NIC}"

	echo -e "\nHere is your client config file as a QR Code:"

	qrencode -t ansiutf8 -l L <"${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	echo "It is also available in ${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
}

function manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Exit"
	until [[ "${MENU_OPTION}" =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed
if [[ -e /etc/wireguard/params ]]; then
	manageMenu
else
	installWireGuard
fi
