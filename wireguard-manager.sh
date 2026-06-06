#!/bin/bash

# WireGuard Management Script
# Based on https://github.com/angristan/wireguard-install
# Modified to manage multiple interfaces without reinstalling WireGuard.

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        echo "You need to run this script as root"
        exit 1
    fi
}

function listExistingInterfaces() {
    # Find all .conf files in /etc/wireguard/ that contain an [Interface] section
    local interfaces=()
    for conf in /etc/wireguard/*.conf; do
        [ -f "$conf" ] || continue
        if grep -q '^\[Interface\]' "$conf"; then
            basename "$conf" .conf
        fi
    done | sort -u
}

function loadParams() {
    local interface="$1"
    # Try per-interface params first, then fallback to legacy /etc/wireguard/params
    if [ -f "/etc/wireguard/params-${interface}" ]; then
        source "/etc/wireguard/params-${interface}"
    elif [ "$interface" = "wg0" ] && [ -f "/etc/wireguard/params" ]; then
        source "/etc/wireguard/params"
        # Ensure variables are named consistently
        SERVER_WG_NIC="$interface"
    else
        echo "Error: No parameter file found for interface '$interface'."
        exit 1
    fi
    # If SERVER_PUB_IP is IPv6, add brackets if missing (needed for client endpoint)
    if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
        if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
            SERVER_PUB_IP="[${SERVER_PUB_IP}]"
        fi
    fi
}

function saveParams() {
    local interface="$1"
    cat > "/etc/wireguard/params-${interface}" <<EOF
SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
WG_MTU=${WG_MTU}
EOF
}

function getHomeDirForClient() {
    local CLIENT_NAME=$1

    if [ -z "${CLIENT_NAME}" ]; then
        echo "Error: getHomeDirForClient() requires a client name as argument"
        exit 1
    fi

    # Home directory of the user, where the client configuration will be written
    # Store client config files in the current directory `./`
    HOME_DIR="./"

    echo "$HOME_DIR"
}

function createInterfaceQuestions() {
    echo "Creating a new WireGuard interface"
    echo "-----------------------------------"
    echo ""

    # Detect public IPv4 or IPv6 address
    SERVER_PUB_IP=$(curl -s https://ipinfo.io/ip)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    # Detect public interface
    SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
    until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
        read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
    done
    
    # Get MTU of the public interface for WireGuard MTU calculation
    if command -v ip &>/dev/null; then
        DEFAULT_MTU=$(ip link show "$SERVER_PUB_NIC" 2>/dev/null | grep -oP 'mtu \K[0-9]+' || echo "1500")
    else
        DEFAULT_MTU=1500
    fi
    # Calculate suggested WireGuard MTU: default NIC MTU - 80 (for WireGuard overhead)
    SUGGESTED_MTU=$((DEFAULT_MTU - 80))
    # Ensure MTU is reasonable (not too small)
    if [ "$SUGGESTED_MTU" -lt 1280 ]; then
        SUGGESTED_MTU=1280
    fi

    # Unique interface name
    local existing
    existing=$(listExistingInterfaces)
    until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]] && \
          ! echo "$existing" | grep -qx "$SERVER_WG_NIC"; do
        read -rp "WireGuard interface name (unique): " -e -i wg1 SERVER_WG_NIC
    done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
		# Check for IP conflict with existing WireGuard interfaces
		if [[ -d /etc/wireguard ]]; then
			for wg_conf in /etc/wireguard/*.conf; do
				if [[ -f "$wg_conf" ]]; then
					existing_ipv4=$(grep -oP 'Address\s*=\s*\K[0-9.]+' "$wg_conf" 2>/dev/null | head -1 || true)
					if [[ -n "$existing_ipv4" ]]; then
						existing_network=$(echo "$existing_ipv4" | cut -d'.' -f1-3)
						new_network=$(echo "$SERVER_WG_IPV4" | cut -d'.' -f1-3)
						if [[ "$existing_network" == "$new_network" ]]; then
							echo -e "${RED}IPv4 network $new_network.0/24 conflicts with existing interface $(basename "$wg_conf")${NC}"
							SERVER_WG_IPV4=""  # Reset to force re-entry
							break
						fi
					fi
				fi
			done
		fi
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
		# Check for IPv6 conflict with existing WireGuard interfaces
		if [[ -d /etc/wireguard ]]; then
			for wg_conf in /etc/wireguard/*.conf; do
				if [[ -f "$wg_conf" ]]; then
					existing_ipv6=$(grep -oP 'Address\s*=\s*\K[0-9a-f:]+' "$wg_conf" 2>/dev/null | grep ':' | head -1 || true)
					if [[ -n "$existing_ipv6" ]]; then
						existing_prefix=$(echo "$existing_ipv6" | cut -d':' -f1-3)
						new_prefix=$(echo "$SERVER_WG_IPV6" | cut -d':' -f1-3)
						if [[ "$existing_prefix" == "$new_prefix" ]]; then
							echo -e "${RED}IPv6 network $new_prefix::/64 conflicts with existing interface $(basename "$wg_conf")${NC}"
							SERVER_WG_IPV6=""  # Reset to force re-entry
							break
						fi
					fi
				fi
			done
		fi
	done

	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "51820" SERVER_PORT
		# Check for port conflict with existing WireGuard interfaces
		if [[ -d /etc/wireguard ]]; then
			for wg_conf in /etc/wireguard/*.conf; do
				if [[ -f "$wg_conf" ]]; then
					existing_port=$(grep -oP 'ListenPort\s*=\s*\K[0-9]+' "$wg_conf" 2>/dev/null || true)
					if [[ "$existing_port" == "$SERVER_PORT" ]]; then
						echo -e "${RED}Port $SERVER_PORT is already in use by $(basename "$wg_conf")${NC}"
						SERVER_PORT=""  # Reset to force re-entry
						break
					fi
				fi
			done
		fi
	done

    until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "First DNS resolver for clients: " -e -i 1.1.1.1 CLIENT_DNS_1
    done
    until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Second DNS resolver for clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
        if [[ ${CLIENT_DNS_2} == "" ]]; then
            CLIENT_DNS_2="${CLIENT_DNS_1}"
        fi
    done

    until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
        echo -e "\nWireGuard uses AllowedIPs to decide what is routed over the VPN."
        read -rp "Allowed IPs list for clients (default routes everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
        if [[ ${ALLOWED_IPS} == "" ]]; then
            ALLOWED_IPS="0.0.0.0/0,::/0"
        fi
    done

    # MTU configuration
    echo -e "\nMTU (Maximum Transmission Unit) configuration:"
    echo "Default interface ${SERVER_PUB_NIC} MTU: ${DEFAULT_MTU}"
    echo "Suggested WireGuard MTU (${DEFAULT_MTU} - 80): ${SUGGESTED_MTU}"
    until [[ ${WG_MTU} =~ ^[0-9]+$ ]] && [ "${WG_MTU}" -ge 1280 ] && [ "${WG_MTU}" -le 9000 ]; do
        read -rp "WireGuard MTU [1280-9000]: " -e -i "${SUGGESTED_MTU}" WG_MTU
    done

    echo ""
    echo "Ready to create interface ${SERVER_WG_NIC}."
    read -n1 -r -p "Press any key to continue..."
}

function createNewInterface() {
    createInterfaceQuestions

    # Generate keys
    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

    # Save parameters for this interface
    saveParams "${SERVER_WG_NIC}"

    # Write server configuration
    cat > "/etc/wireguard/${SERVER_WG_NIC}.conf" <<EOF
[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
MTU = ${WG_MTU}
EOF

    # Add firewall rules (PostUp/PostDown)
    if pgrep firewalld; then
        FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" <<EOF
PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
EOF
    else
        cat >> "/etc/wireguard/${SERVER_WG_NIC}.conf" <<EOF
PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
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
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF
    fi

    # Enable IP forwarding (global)
    if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.d/wg.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.d/wg.conf
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/wg.conf
        sysctl --system
    fi

    # Start and enable the interface
    systemctl start "wg-quick@${SERVER_WG_NIC}"
    systemctl enable "wg-quick@${SERVER_WG_NIC}"

    echo -e "${GREEN}Interface ${SERVER_WG_NIC} created and started.${NC}"
    echo -e "You can now add clients by managing this interface."
}

function addClient() {
    local interface="$1"
    loadParams "$interface"

    echo ""
    echo "Add a new client for interface ${interface}"
    echo "------------------------------------------"
    echo "Client name must be alphanumeric + underscores/dashes, max 15 chars."

    local CLIENT_NAME
    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${#CLIENT_NAME} -lt 16 ]]; do
        read -rp "Client name: " -e CLIENT_NAME
        if grep -q "^### Client ${CLIENT_NAME}$" "/etc/wireguard/${interface}.conf"; then
            echo -e "${ORANGE}A client with that name already exists.${NC}"
            CLIENT_NAME=""
        fi
    done

    # Find next available IPv4 address
    local BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
    local DOT_IP
    for (( DOT_IP=2; DOT_IP<=254; DOT_IP++ )); do
        if ! grep -q "${BASE_IP}.${DOT_IP}/32" "/etc/wireguard/${interface}.conf"; then
            break
        fi
    done
    if [ $DOT_IP -eq 255 ]; then
        echo "Subnet full (max 253 clients)."
        exit 1
    fi
    local CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"

    # Next available IPv6 address
    local BASE_IP6=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
    local CLIENT_WG_IPV6="${BASE_IP6}::${DOT_IP}"
    while grep -q "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${interface}.conf"; do
        (( DOT_IP++ ))
        CLIENT_WG_IPV6="${BASE_IP6}::${DOT_IP}"
    done

    # Generate client keys
    CLIENT_PRIV_KEY=$(wg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
    CLIENT_PRE_SHARED_KEY=$(wg genpsk)

    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    CLIENT_CONF="${HOME_DIR}/${interface}-client-${CLIENT_NAME}.conf"

    cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}
MTU = ${WG_MTU}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = 25
EOF

    # Add peer to server config
    cat >> "/etc/wireguard/${interface}.conf" <<EOF

### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
EOF

    # Reload WireGuard
    wg syncconf "${interface}" <(wg-quick strip "${interface}")

    # Show QR code if qrencode is available
    if command -v qrencode &>/dev/null; then
        echo -e "${GREEN}\nClient configuration as QR Code:${NC}"
        qrencode -t ansiutf8 -l L < "$CLIENT_CONF"
        echo ""
    fi

    echo -e "${GREEN}Client config saved to: ${CLIENT_CONF}${NC}"
}

function listClients() {
    local interface="$1"
    local count=$(grep -c "^### Client" "/etc/wireguard/${interface}.conf")
    if [ $count -eq 0 ]; then
        echo "No clients defined for interface ${interface}."
        return
    fi
    echo "Clients for ${interface}:"
    grep "^### Client" "/etc/wireguard/${interface}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
    local interface="$1"
    local count=$(grep -c "^### Client" "/etc/wireguard/${interface}.conf")
    if [ $count -eq 0 ]; then
        echo "No clients to revoke."
        return
    fi

    echo "Select a client to revoke:"
    grep "^### Client" "/etc/wireguard/${interface}.conf" | cut -d ' ' -f 3 | nl -s ') '
    local CLIENT_NUMBER
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${count} ]]; do
        read -rp "Client number: " CLIENT_NUMBER
    done

    local CLIENT_NAME
    CLIENT_NAME=$(grep "^### Client" "/etc/wireguard/${interface}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}p")

    # Remove peer block
    sed -i "/^### Client ${CLIENT_NAME}$/,/^$/d" "/etc/wireguard/${interface}.conf"

    # Delete client config file
    rm -f "./${interface}-client-${CLIENT_NAME}.conf"

    # Reload WireGuard
    wg syncconf "${interface}" <(wg-quick strip "${interface}")

    echo -e "${GREEN}Client ${CLIENT_NAME} revoked.${NC}"
}

function showClientConf() {
    local interface="$1"
    local count=$(grep -c "^### Client" "/etc/wireguard/${interface}.conf")
    if [ $count -eq 0 ]; then
        echo "No clients defined for interface ${interface}."
        return
    fi

    echo "Select a client to view configuration:"
    grep "^### Client" "/etc/wireguard/${interface}.conf" | cut -d ' ' -f 3 | nl -s ') '
    local CLIENT_NUMBER
    until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${count} ]]; do
        read -rp "Client number: " CLIENT_NUMBER
    done

    local CLIENT_NAME
    CLIENT_NAME=$(grep "^### Client" "/etc/wireguard/${interface}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}p")

    # Get client configuration file path
    local HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    local CLIENT_CONF="${HOME_DIR}/${interface}-client-${CLIENT_NAME}.conf"

    if [[ ! -f "$CLIENT_CONF" ]]; then
        echo -e "${RED}Client configuration file not found: $CLIENT_CONF${NC}"
        return
    fi

    echo ""
    echo "Select configuration mode:"
    echo "   1) Normal mode (full VPN)"
    echo "   2) VLAN mode (wireguard subnet only)"
    local MODE_OPTION
    until [[ ${MODE_OPTION} =~ ^[1-2]$ ]]; do
        read -rp "Select mode [1-2]: " MODE_OPTION
    done

    echo ""
    echo "Client configuration for ${CLIENT_NAME}:"
    echo "========================================"

    if [[ ${MODE_OPTION} == '1' ]]; then
        # Normal mode - show original config
        cat "$CLIENT_CONF"
    else
        # VLAN mode - modify config
        # Load params to get server IPs
        loadParams "$interface"
        
        # Read the original config
        config_content=$(cat "$CLIENT_CONF")
        
        # Remove DNS line
        config_content=$(echo "$config_content" | grep -v '^DNS = ')
        
        # Modify AllowedIPs to wireguard subnet only
        # Get server subnet from SERVER_WG_IPV4 and SERVER_WG_IPV6
        SERVER_SUBNET_IPV4=$(echo "$SERVER_WG_IPV4" | cut -d'.' -f1-3)".0/24"
        SERVER_SUBNET_IPV6=$(echo "$SERVER_WG_IPV6" | cut -d':' -f1-3)"::/64"
        
        # Replace AllowedIPs line
        config_content=$(echo "$config_content" | sed "s|AllowedIPs = .*|AllowedIPs = ${SERVER_SUBNET_IPV4}, ${SERVER_SUBNET_IPV6}|")
        
        # Ensure PersistentKeepalive is set to 25
        if ! echo "$config_content" | grep -q "PersistentKeepalive = 25"; then
            config_content=$(echo "$config_content" | sed '/PersistentKeepalive =/d')
            config_content=$(echo "$config_content" | sed "s|\(AllowedIPs = .*\)|\1\nPersistentKeepalive = 25|")
        fi
        
        echo "$config_content"
    fi
    
    echo ""
    echo "========================================"
}

function removeInterface() {
    local interface="$1"
    echo -e "${RED}WARNING: This will stop and remove WireGuard interface '${interface}' and its configuration.${NC}"
    read -rp "Are you sure? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted."
        return
    fi

    systemctl stop "wg-quick@${interface}"
    systemctl disable "wg-quick@${interface}"

    rm -f "/etc/wireguard/${interface}.conf"
    rm -f "/etc/wireguard/params-${interface}"

    echo -e "${GREEN}Interface ${interface} removed.${NC}"
}

function manageInterface() {
    local interface="$1"
    while true; do
        echo ""
        echo "Managing WireGuard interface: ${interface}"
        echo "----------------------------------------"
        echo "1) Add a new client"
        echo "2) List all clients"
        echo "3) Show client configuration"
        echo "4) Revoke a client"
        echo "5) Remove this interface"
        echo "6) Back to main menu"
        read -rp "Select option [1-6]: " opt
        case $opt in
            1) addClient "$interface" ;;
            2) listClients "$interface" ;;
            3) showClientConf "$interface" ;;
            4) revokeClient "$interface" ;;
            5) removeInterface "$interface"; break ;;
            6) break ;;
            *) echo "Invalid option." ;;
        esac
    done
}

function mainMenu() {
    while true; do
        echo ""
        echo "WireGuard Management Script"
        echo "==========================="
        echo "1) Manage an existing interface"
        echo "2) Create a new WireGuard interface"
        echo "3) Exit"
        read -rp "Select option [1-3]: " choice
        case $choice in
            1)
                mapfile -t ifaces < <(listExistingInterfaces)
                if [ ${#ifaces[@]} -eq 0 ]; then
                    echo "No WireGuard interfaces found in /etc/wireguard/."
                    echo "Create one first (option 2)."
                    continue
                fi
                echo "Available interfaces:"
                for i in "${!ifaces[@]}"; do
                    echo "$((i+1))) ${ifaces[i]}"
                done
                read -rp "Select interface: " idx
                if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#ifaces[@]}" ]; then
                    manageInterface "${ifaces[$((idx-1))]}"
                else
                    echo "Invalid selection."
                fi
                ;;
            2)
                createNewInterface
                ;;
            3)
                echo "Exiting."
                exit 0
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
    done
}

# Entry point
isRoot
mainMenu