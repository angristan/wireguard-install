#!/bin/bash
#
# About: Install WireGuard automatically
# Author: angristan
# Thanks : shyamjos, outis151, Leopere, ucawen, Shagon94, shoujii, liberodark
# License: MIT

version="1.0.0"

echo "Welcome on WireGuard Install Script $version"

#=================================================
# CHECK ROOT
#=================================================

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

distribution=$(cat /etc/*release | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//g' | sed 's/["]//g' | awk '{print $1}')

usage ()
{
     echo "usage: -install or -remove"
     echo "options:"
     echo "-install: Install WireGuard"
     echo "-remove: Remove WireGuard"
     echo "-h: Show help"
}

detect_bad(){
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
}

options(){
# Detect public IPv4 address and pre-fill for the user
SERVER_PUB_IPV4=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
read -rp "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IPV4" SERVER_PUB_IP

# Detect public interface and pre-fill for the user
SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
read -rp "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC

SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

SERVER_WG_IPV4="10.66.66.1"
read -rp "Server's WireGuard IPv4 " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

SERVER_WG_IPV6="fd42:42:42::1"
read -rp "Server's WireGuard IPv6 " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

SERVER_PORT=1194
read -rp "Server's WireGuard port " -e -i "$SERVER_PORT" SERVER_PORT

CLIENT_WG_IPV4="10.66.66.2"
read -rp "Client's WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4" CLIENT_WG_IPV4

CLIENT_WG_IPV6="fd42:42:42::2"
read -rp "Client's WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6" CLIENT_WG_IPV6

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"
read -rp "First DNS resolver to use for the client: " -e -i "$CLIENT_DNS_1" CLIENT_DNS_1

CLIENT_DNS_2="176.103.130.131"
read -rp "Second DNS resolver to use for the client: " -e -i "$CLIENT_DNS_2" CLIENT_DNS_2

# Ask for pre-shared symmetric key
IS_PRE_SYMM="y"
read -rp "Want to use pre-shared symmetric key? [Y/n]: " -e -i "$IS_PRE_SYMM" IS_PRE_SYMM

if [[ $SERVER_PUB_IP =~ .*:.* ]]
then
  echo "IPv6 Detected"
  ENDPOINT="[$SERVER_PUB_IP]:$SERVER_PORT"
else
  echo "IPv4 Detected"
  ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"
fi
}

remove_wg(){
echo "Remove WireGuard Server ($distribution)"

  # Check OS & WireGuard

  if command -v wg-quick > /dev/null 2>&1; then

    if [ "$distribution" = "CentOS" ] || [ "$distribution" = "Red\ Hat" ] || [ "$distribution" = "Oracle" ]; then
      systemctl stop wg-quick@wg0.service > /dev/null 2>&1
      systemctl disable wg-quick@wg0.service > /dev/null 2>&1
      sudo rm /etc/yum.repos.d/wireguard.repo
      yum remove -y wireguard-dkms wireguard-tools > /dev/null 2>&1
      rm -rf /etc/wireguard
      rm /etc/sysctl.d/wg.conf
      
    elif [ "$distribution" = "Fedora" ]; then
      systemctl stop wg-quick@wg0.service > /dev/null 2>&1
      systemctl disable wg-quick@wg0.service > /dev/null 2>&1
      dnf copr disable jdoss/wireguard > /dev/null 2>&1
      dnf remove -y wireguard-dkms wireguard-tools iptables > /dev/null 2>&1
      rm -rf /etc/wireguard
      rm /etc/sysctl.d/wg.conf
    
    elif [ "$distribution" = "Ubuntu" ] || [ "$distribution" = "Deepin" ]; then
      systemctl stop wg-quick@wg0.service > /dev/null 2>&1
      systemctl disable wg-quick@wg0.service > /dev/null 2>&1
      apt-get remove -y wireguard --force-yes > /dev/null 2>&1
      rm -rf /etc/wireguard
      rm /etc/sysctl.d/wg.conf

    elif [ "$distribution" = "Debian" ] || [ "$distribution" = "Raspbian" ]; then
      systemctl stop wg-quick@wg0.service > /dev/null 2>&1
      systemctl disable wg-quick@wg0.service > /dev/null 2>&1
      apt-get install -y wireguard iptables --force-yes > /dev/null 2>&1
      rm -rf /etc/wireguard
      rm /etc/sysctl.d/wg.conf
      
    elif [ "$distribution" = "Manjaro" ] || [ "$distribution" = "Arch\ Linux" ]; then
      systemctl stop wg-quick@wg0.service > /dev/null 2>&1
      systemctl disable wg-quick@wg0.service > /dev/null 2>&1
      pacman -R wireguard-dkms wireguard-tools --noconfirm > /dev/null 2>&1
      rm -rf /etc/wireguard
      rm /etc/sysctl.d/wg.conf

    fi
fi
}

install_wg(){
echo "Install WireGuard Server ($distribution)"

  # Check OS & WireGuard

  if ! command -v wg-quick > /dev/null 2>&1; then

    if [ "$distribution" = "CentOS" ] || [ "$distribution" = "Red\ Hat" ] || [ "$distribution" = "Oracle" ]; then
      curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo > /dev/null 2>&1
      yum install -y epel-release > /dev/null 2>&1
      yum install -y wireguard-dkms wireguard-tools iptables > /dev/null 2>&1
      
    elif [ "$distribution" = "Fedora" ]; then
      dnf copr enable jdoss/wireguard > /dev/null 2>&1
      dnf install -y wireguard-dkms wireguard-tools iptables > /dev/null 2>&1
    
    elif [ "$distribution" = "Ubuntu" ] || [ "$distribution" = "Deepin" ]; then
      add-apt-repository ppa:wireguard/wireguard
      apt-get update > /dev/null 2>&1
      apt-get install -y "linux-headers-$(uname -r)" > /dev/null 2>&1
      apt-get install -y wireguard iptables resolvconf --force-yes > /dev/null 2>&1

    elif [ "$distribution" = "Debian" ] || [ "$distribution" = "Raspbian" ]; then
      add-apt-repository ppa:wireguard/wireguard
      apt-get update > /dev/null 2>&1
      apt-get install -y "linux-headers-$(uname -r)" > /dev/null 2>&1
      apt-get install -y wireguard iptables resolvconf --force-yes > /dev/null 2>&1
      
    elif [ "$distribution" = "Manjaro" ] || [ "$distribution" = "Arch\ Linux" ]; then
      pacman -S linux-headers dkms --noconfirm > /dev/null 2>&1
      pacman -S wireguard-dkms wireguard-tools iptables openresolv --noconfirm > /dev/null 2>&1

    fi
fi
}

configure_wg(){
# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard > /dev/null 2>&1

# Generate key pair for the server
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE" > "/etc/wireguard/$SERVER_WG_NIC.conf"

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
echo "
[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >> "$HOME/$SERVER_WG_NIC-client.conf"

# Add pre shared symmetric key to respective files
case "$IS_PRE_SYMM" in
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
}

arg_install_wg(){
# Install WireGuard
detect_bad
options
install_wg
configure_wg
}

arg_remove_wg(){
# Remove WireGuard
detect_bad
remove_wg
}

parse_args ()
{
    while [ $# -ne 0 ]
    do
        case "${1}" in
            -install)
                shift
                arg_install_wg >&2
                ;;
            -remove)
                shift
                arg_remove_wg >&2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Invalid argument : ${1}" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done

}

parse_args "$@"
