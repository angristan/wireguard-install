#!/bin/bash

# This adds an additional client based on the last created client config file in the current
# directory


nextip(){
    IP=$1
    IP_HEX=$(printf '%.2X%.2X%.2X%.2X\n' `echo $IP | sed -e 's/\./ /g'`)
    NEXT_IP_HEX=$(printf %.8X `echo $(( 0x$IP_HEX + 1 ))`)
    NEXT_IP=$(printf '%d.%d.%d.%d\n' `echo $NEXT_IP_HEX | sed -r 's/(..)/0x\1 /g'`)
    echo "$NEXT_IP"
}

nextipv6(){
    IP=$1
    IP_HEX=$(ipv6calc -q --printfulluncompresse $1 | sed -e 's/\://g' | tr [a-f] [A-f] )
    NEXT_IP_HEX=`echo "obase=16 ; ibase=16; $IP_HEX + 1" | bc`
    echo ${NEXT_IP_HEX:0:4}:${NEXT_IP_HEX:4:4}:${NEXT_IP_HEX:8:4}:${NEXT_IP_HEX:12:4}:${NEXT_IP_HEX:16:4}:${NEXT_IP_HEX:20:4}:${NEXT_IP_HEX:24:4}:${NEXT_IP_HEX:28:4}/64 | ipv6calc --printcompressed
}

if [ "$EUID" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit
fi

if [ "$(systemd-detect-virt)" == "lxc" ]; then
    echo "LXC is not supported (yet)."
    echo "WireGuard can technically run in an LXC container,"
    echo "but the kernel module has to be installed on the host,"
    echo "the container has to be run with some specific parameters"
    echo "and only the tools need to be installed in the container."
    exit
fi

# Check OS version
if [[ -e /etc/debian_version ]]; then
    source /etc/os-release
    OS=$ID # debian or ubuntu
elif [[ -e /etc/fedora-release ]]; then
    OS=fedora
elif [[ -e /etc/centos-release ]]; then
    OS=centos
elif [[ -e /etc/arch-release ]]; then
    OS=arch
else
    echo "Looks like you aren't running this script on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
    exit 1
fi

# Install tools

if [[ ! $(which ipv6calc) ]]; then
    if [[ "$OS" = 'ubuntu' ]]; then
        apt-get install -y "ipv6calc"
    elif [[ "$OS" = 'debian' ]]; then
        apt-get install -y "ipv6calc"
    elif [[ "$OS" = 'arch' ]]; then
        pacman -Sy --noconfirm ipv6calc
    fi
fi

SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC


if [[ -e /etc/wireguard/$SERVER_WG_NIC.conf ]]; then
	WG_SERVER_CONF="/etc/wireguard/$SERVER_WG_NIC.conf"
else
	echo "Looks like there is no configuration at $WG_SERVER_CONF for wireguard interface $SERVER_WG_NIC"
	exit 1
fi

CLIENT_WG_NAME=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-16)
read -rp "WireGuard client name: " -e -i "$CLIENT_WG_NAME" CLIENT_WG_NAME

CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

SERVER_PUB_KEY=$(wg | grep 'public key' | head -n 1 | sed 's/public key: //')

SERVER_ENDPOINT=$(cat *-client.conf | grep 'Endpoint' | head -n1 | sed 's/Endpoint = //')

PRESHARED_KEY=$(cat *-client.conf | grep 'PresharedKey' | head -n1 | sed 's/PresharedKey = //')

LAST_IP=$( cat $(ls -t *-client.conf | head -n1) | grep Address | sed 's/Address = //' | cut -d ',' -f1 | sed 's/\/24//' )
CLIENT_WG_IPV4=$( nextip $LAST_IP )
read -rp "Client's WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4" CLIENT_WG_IPV4

LAST_IPV6=$(cat $(ls -t *-client.conf | head -n1) | grep Address | sed 's/Address = //' | cut -d ',' -f2 | sed 's/\/64//')
CLIENT_WG_IPV6=$( nextipv6 $LAST_IPV6 | sed 's/\/64//' )
read -rp "Client's WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6" CLIENT_WG_IPV6

# Adguard last added clients dns by default.
# echo "Enterprise users should use there internal DNS Servers in Windows environments this are usually the domain controllers"

CLIENT_DNS=$(cat *-client.conf | grep 'DNS = ' | head -n1 | sed 's/DNS = //')

# Add the client as a peer to the server
echo "
[Peer]
# $CLIENT_WG_NAME
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128" >> "/etc/wireguard/$SERVER_WG_NIC.conf"

# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_WG_IPV4/24,$CLIENT_WG_IPV6/64
DNS = $CLIENT_DNS" > "$HOME/$CLIENT_WG_NAME-client.conf"

# Add the server as a peer to the client
echo "
[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $SERVER_ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >> "$HOME/$CLIENT_WG_NAME-client.conf"

if [[ $PRESHARED_KEY ]]; then
# Add pre shared symmetric key to client-conf file
        echo "PresharedKey = $PRESHARED_KEY" >> "$HOME/$CLIENT_WG_NAME-client.conf"
fi

qrencode -t ansiutf8 -l L < "$HOME/$CLIENT_WG_NAME-client.conf"
