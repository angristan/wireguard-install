#!/bin/bash

SERVER_WG_NIC="wg0"
SERVER_PUB_NIC="ens3"
SERVER_WG_IPV4="10.66.66.1"
SERVER_WG_IPV6="fd42:42:42::1"
#SERVER_PUB_IPV4=""
SERVER_PORT=1194

CLIENT_IPV4="10.66.66.2"
CLIENT_IPV6="fd42:42:42::2"

add-apt-repository -y ppa:wireguard/wireguard
apt-get install -y wireguard

SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
PostUp = iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE" > /etc/wireguard/$SERVER_WG_NIC.conf

# Add the client as a peer to the server
echo "[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = $CLIENT_IPV4/32,$CLIENT_IPV6/128" >> /etc/wireguard/$SERVER_WG_NIC.conf

# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_IPV4/24,$CLIENT_IPV6/64" > ~/$SERVER_WG_NIC-client.conf

# Add the server as a peer to the client
echo "[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $SERVER_PUB_IPV4:1194
AllowedIPs = 0.0.0.0/0,::/0" >> ~/$SERVER_WG_NIC-client.conf

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/wg.conf

sysctl --system

systemctl start "wg-quick@$SERVER_WG_NIC"
systemctl enable "wg-quick@$SERVER_WG_NIC"
