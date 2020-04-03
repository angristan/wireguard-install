#!/bin/bash

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
    source /etc/os-release
    OS=$ID
elif [[ -e /etc/centos-release ]]; then
    OS=centos
elif [[ -e /etc/arch-release ]]; then
    OS=arch
else
    echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
    exit 1
fi

# Detect public IPv4 address and pre-fill for the user
SERVER_PUB_IPV4=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
read -rp "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IPV4" SERVER_PUB_IP

# Detect public interface and pre-fill for the user
SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
read -rp "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC

SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

SERVER_WG_IPV4="10.66.66.1"
read -rp "Server's WireGuard IPv4: " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

SERVER_WG_IPV6="fd42:42:42::1"
read -rp "Server's WireGuard IPv6: " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

# Generate random number within private ports range
SERVER_PORT=$(shuf -i49152-65535 -n1)
read -rp "Server's WireGuard port: " -e -i "$SERVER_PORT" SERVER_PORT

CLIENT_WG_IPV4="10.66.66.2"
read -rp "Client's WireGuard IPv4: " -e -i "$CLIENT_WG_IPV4" CLIENT_WG_IPV4

CLIENT_WG_IPV6="fd42:42:42::2"
read -rp "Client's WireGuard IPv6: " -e -i "$CLIENT_WG_IPV6" CLIENT_WG_IPV6

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"
read -rp "First DNS resolver to use for the client: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

CLIENT_DNS_2="176.103.130.131"
read -rp "Second DNS resolver to use for the client: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2

SYM_KEY="y"
read -rp "Want to use a pre-shared symmetric key? [Y/n]: " -e -i "$SYM_KEY" SYM_KEY

if [[ $SERVER_PUB_IP =~ .*:.* ]]
then
  echo "IPv6 Detected"
  ENDPOINT="[$SERVER_PUB_IP]:$SERVER_PORT"
else
  echo "IPv4 Detected"
  ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"
fi

# Install WireGuard tools and module
if [[ "$OS" = 'ubuntu' ]]; then
    apt-get install -y software-properties-common
    add-apt-repository -y ppa:wireguard/wireguard
    apt-get update
    apt-get install -y "linux-headers-$(uname -r)"
    apt-get install -y wireguard iptables resolvconf qrencode
elif [[ "$OS" = 'debian' ]]; then
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt update
    apt-get install -y "linux-headers-$(uname -r)"
    apt-get install -y wireguard iptables resolvconf qrencode
elif [[ "$OS" = 'fedora' ]]; then
    if [[ "$VERSION_ID" -lt 32 ]]; then
        dnf install -y dnf-plugins-core
        dnf copr enable -y jdoss/wireguard
        dnf install -y wireguard-dkms
    fi
    dnf install -y wireguard-tools iptables qrencode
elif [[ "$OS" = 'centos' ]]; then
    curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    yum -y install epel-release
    yum -y install wireguard-dkms wireguard-tools iptables qrencode
elif [[ "$OS" = 'arch' ]]; then
    pacman -S --noconfirm linux-headers
    pacman -S --noconfirm wireguard-tools iptables wireguard-arch qrencode
fi

# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard > /dev/null 2>&1

# Generate key pair for the server
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Generate key pair for the server
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY" > "/etc/wireguard/$SERVER_WG_NIC.conf"

if [ -x "$(command -v firewall-cmd)" ]; then
    FIREWALLD_IPV4_ADDRESS=$(echo "$SERVER_WG_IPV4" | cut -d"." -f1-3)".0"
    FIREWALLD_IPV6_ADDRESS=$(echo "$SERVER_WG_IPV6" | sed 's/:[^:]*$/:0/')
    echo "PostUp = firewall-cmd --add-port $SERVER_PORT/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=$FIREWALLD_IPV4_ADDRESS/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=$FIREWALLD_IPV6_ADDRESS/24 masquerade'
PostDown = firewall-cmd --remove-port $SERVER_PORT/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=$FIREWALLD_IPV4_ADDRESS/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=$FIREWALLD_IPV6_ADDRESS/24 masquerade'" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
else
    echo "PostUp = iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
fi

# Add the client as a peer to the server
echo "[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = $CLIENT_WG_IPV4/32,$CLIENT_WG_IPV6/128" >> "/etc/wireguard/$SERVER_WG_NIC.conf"

# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_WG_IPV4/24,$CLIENT_WG_IPV6/64
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2" > "$HOME/$SERVER_WG_NIC-client.conf"

# Add the server as a peer to the client
echo "[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >> "$HOME/$SERVER_WG_NIC-client.conf"

# Add pre shared symmetric key to respective files
case "$SYM_KEY" in
    [yY][eE][sS]|[yY])
        CLIENT_SYMM_PRE_KEY=$( wg genpsk )
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$HOME/$SERVER_WG_NIC-client.conf"
        ;;
esac

chmod 600 -R /etc/wireguard/

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/wg.conf

sysctl --system

systemctl start "wg-quick@$SERVER_WG_NIC"
systemctl enable "wg-quick@$SERVER_WG_NIC"

echo -e "\nHere is your client config file as a QR Code:"

qrencode -t ansiutf8 -l L < "$HOME/$SERVER_WG_NIC-client.conf"

# Check if WireGuard is running
systemctl is-active --quiet "wg-quick@$SERVER_WG_NIC"
WG_RUNNING=$?

# Warn user about kernel version mismatch with headers
if [[ "$OS" =~ (fedora|centos) ]] && [[ $WG_RUNNING -ne 0 ]]; then
    echo -e "\nWARNING: WireGuard does not seem to be running."
    echo "Due to kernel mismatch issues on $OS, WireGuard might work if your system is out of date."
    echo "You can check if WireGuard is running with: systemctl status wg-quick@$SERVER_WG_NIC"
    echo "If you get something like \"Cannot find device wg0\", please run:"
    if [[ "$OS" = 'fedora' ]]; then
        echo "dnf update -y && reboot"
    elif [[ "$OS" = 'centos' ]]; then
        echo "yum update -y && reboot"
    fi
fi
