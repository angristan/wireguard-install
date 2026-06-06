#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

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



function initialCheck() {
	isRoot
	checkOS
	checkVirt
}



function installWireGuard() {
	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		installPackages apt-get install -y curl wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt-get update
		installPackages apt-get install -y curl iptables resolvconf qrencode
		installPackages apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			installPackages dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			installPackages dnf install -y wireguard-dkms
		fi
		installPackages dnf install -y curl wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			installPackages yum install -y epel-release elrepo-release
			installPackages yum install -y kmod-wireguard
			yum install -y qrencode || true # not available on release 9
		fi
		installPackages yum install -y curl wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		installPackages dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		installPackages dnf install -y curl wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		installPackages pacman -S --needed --noconfirm curl wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		installPackages apk add curl wireguard-tools iptables libqrencode-tools
	fi

	# Verify WireGuard installation
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}WireGuard installation failed. The 'wg' command was not found.${NC}"
		echo "Please check the installation output above for errors."
		exit 1
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1
	chmod 600 -R /etc/wireguard/

	# Enable IP forwarding globally (required for WireGuard routing)
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf
	sysctl --system

	# OS-specific permissions (optional)
	if [[ ${OS} == 'fedora' ]]; then
		chmod -v 700 /etc/wireguard
		chmod -v 600 /etc/wireguard/*
	fi

	echo -e "${GREEN}WireGuard has been successfully installed!${NC}"
	echo ""
	echo "To set up your first WireGuard interface, please run:"
	echo "  ./wireguard-manager.sh"
	echo ""
	echo "This manager will guide you through creating interfaces and adding clients."
}













# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed
if command -v wg &>/dev/null; then
	echo -e "${GREEN}WireGuard is already installed.${NC}"
	echo "To manage interfaces and clients, please run:"
	echo "  ./wireguard-manager.sh"
	exit 0
else
	installWireGuard
fi
