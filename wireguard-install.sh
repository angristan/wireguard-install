#!/bin/bash

# Secure WireGuard server installer
# https://github.com/Cormaxs/wireguard-install-update-update-update

# Habilitar el modo de salida inmediata en caso de error para mayor robustez
set -e

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- Configuración para la auto-instalación ---
TARGET_INSTALL_PATH="/usr/local/bin/wg-menu"

# Función para verificar si se ejecuta como root
function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo -e "${RED}Necesitas ejecutar este script como root. Por favor, usa 'sudo' o ejecuta como usuario root.${NC}"
		exit 1
	fi
}

# --- Lógica de Auto-instalación ---
# Verifica si el script no está ya en la ubicación final y si su nombre de ejecución no es 'wg-menu'
# El || true al final de command -v es para evitar que set -e detenga el script si el comando no existe.
if [[ "$(basename "$0")" != "wg-menu" || "$(readlink -f "$0")" != "${TARGET_INSTALL_PATH}" ]]; then
	# Solo intenta instalar si el comando 'wg-menu' no existe o si apunta a una ubicación diferente
	local WG_MENU_COMMAND_EXISTS
	command -v wg-menu &>/dev/null && WG_MENU_COMMAND_EXISTS=0 || WG_MENU_COMMAND_EXISTS=1

	if [ "${WG_MENU_COMMAND_EXISTS}" -ne 0 ] || [[ "$(readlink -f "$(command -v wg-menu 2>/dev/null || true)")" != "${TARGET_INSTALL_PATH}" ]]; then
		echo -e "${GREEN}Detectado que el script no está instalado como 'wg-menu'.${NC}"
		echo -e "${ORANGE}Intentando auto-instalación en ${TARGET_INSTALL_PATH}...${NC}"

		isRoot # Asegura privilegios de root para la instalación

		# Asegura que el script actual tenga permisos de ejecución antes de moverlo
		chmod +x "$0"

		if sudo mv "$0" "${TARGET_INSTALL_PATH}"; then
			sudo chmod +x "${TARGET_INSTALL_PATH}"
			echo -e "${GREEN}Script instalado exitosamente como 'wg-menu'.${NC}"
			echo -e "${GREEN}Ahora puedes simplemente ejecutar 'wg-menu' desde cualquier directorio.${NC}"
			echo -e "${ORANGE}Re-ejecutando el script desde su nueva ubicación...${NC}"
			# Re-ejecuta el script desde su nueva ubicación, pasando todos los argumentos
			exec "${TARGET_INSTALL_PATH}" "$@"
		else
			echo -e "${RED}Falló al mover el script a ${TARGET_INSTALL_PATH}. Por favor, verifica los permisos.${NC}"
			echo "Puedes intentar instalarlo manualmente con:"
			echo "   sudo mv \"$(basename "$0")\" \"${TARGET_INSTALL_PATH}\""
			echo "   sudo chmod +x \"${TARGET_INSTALL_PATH}\""
			exit 1
		fi
	fi
fi

# A partir de aquí, el script asume que se está ejecutando como 'wg-menu' o que ya pasó la auto-instalación.

function openvzErr() {
	echo -e "${RED}OpenVZ no es compatible.${NC}"
	exit 1
}
function lxcErr() {
	echo -e "${RED}LXC no es compatible (aún).${NC}"
	echo "WireGuard técnicamente puede ejecutarse en un contenedor LXC,"
	echo "pero el módulo del kernel debe instalarse en el host,"
	echo "el contenedor debe ejecutarse con algunos parámetros específicos"
	echo "y solo las herramientas necesitan instalarse en el contenedor."
	exit 1
}

function checkVirt() {
	local VIRT_WHAT_EXISTS
	command -v virt-what &>/dev/null && VIRT_WHAT_EXISTS=0 || VIRT_WHAT_EXISTS=1

	if [ "${VIRT_WHAT_EXISTS}" -eq 0 ]; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		# systemd-detect-virt puede no estar presente en todas las distribuciones o configuraciones,
		# así que se usa '|| true' para evitar que set -e detenga el script si el comando no existe.
		if [ "$(systemd-detect-virt || true)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt || true)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

# verifica si el S.O es valido
function checkOS() {
	source /etc/os-release || {
		echo -e "${RED}No se pudo cargar /etc/os-release. ¿Sistema operativo compatible?${NC}"
		exit 1
	}
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo -e "${RED}Tu versión de Debian (${VERSION_ID}) no es compatible. Por favor, usa Debian 10 Buster o posterior.${NC}"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo -e "${RED}Tu versión de Ubuntu (${VERSION_ID}) no es compatible. Por favor, usa Ubuntu 18.04 o posterior.${NC}"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo -e "${RED}Tu versión de Fedora (${VERSION_ID}) no es compatible. Por favor, usa Fedora 32 o posterior.${NC}"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo -e "${RED}Tu versión de CentOS (${VERSION_ID}) no es compatible. Por favor, usa CentOS 8 o posterior.${NC}"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release || {
			echo -e "${RED}No se pudo cargar /etc/os-release para Oracle Linux.${NC}"
			exit 1
		}
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			echo -e "${ORANGE}Instalando virt-what para detección de virtualización...${NC}"
			apk update && apk add virt-what
		fi
	else
		echo -e "${RED}Parece que no estás ejecutando este instalador en un sistema Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle o Arch Linux.${NC}"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1
	local HOME_DIR_VAR

	if [ -z "${CLIENT_NAME}" ]; then
		echo -e "${RED}Error: getHomeDirForClient() requiere un nombre de cliente como argumento.${NC}"
		exit 1
	fi

	if id -u "${CLIENT_NAME}" &>/dev/null; then
		# If $CLIENT_NAME is an existing user
		HOME_DIR_VAR=$(eval echo "~${CLIENT_NAME}")
	elif [ -n "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ]; then
		# If run via sudo by a non-root user
		HOME_DIR_VAR=$(eval echo "~${SUDO_USER}")
	else
		# Default to /root if no other user or SUDO_USER is root
		HOME_DIR_VAR="/root"
	fi
	echo "$HOME_DIR_VAR"
}

#antes de instalar verifica
function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

# --- Mejoras en la gestión de DNS ---

# Función para validar si una entrada es una dirección IP válida
function validateIp() {
	local ip=$1
	local stat=1

	# Validación IPv4
	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		IFS='.' read -r i j k l <<<"$ip"
		if ((i <= 255 && j <= 255 && k <= 255 && l <= 255)); then
			stat=0
		fi
	# Validación IPv6 simplificada, cubre los formatos válidos más comunes pero no todos los casos extremos (ej. IPv4-in-IPv6)
	elif [[ $ip =~ ^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$ || $ip =~ ^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$ || $ip =~ ^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}|:)$ || $ip =~ ^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$ || $ip =~ ^::[0-9a-fA-F]{1,4}$ ]]; then
		stat=0
	fi
	return "$stat"
}

# Función para mostrar opciones de DNS y permitir al usuario elegir
function showDnsOptions() {
	echo ""
	echo "Elige un resolvedor DNS para tus clientes:"
	echo "   1) Cloudflare (1.1.1.1, 1.0.0.1): Rápido, enfocado en la privacidad."
	echo "   2) Google (8.8.8.8, 8.8.4.4): Confiable y ampliamente utilizado."
	echo "   3) OpenDNS (208.67.222.222, 208.67.220.220): Ofrece controles parentales y protección contra phishing."
	echo "   4) AdGuard DNS (94.140.14.14, 94.140.15.15): Bloquea anuncios y rastreadores."
	echo "   5) DNS Personalizado: Introduce tu(s) propio(s) servidor(es) DNS."
	echo "   6) Sin DNS (No Recomendado): Los clientes no tendrán acceso a internet a través de la VPN si no se configura DNS."

	local dns_choice
	until [[ ${dns_choice} =~ ^[1-6]$ ]]; do
		read -rp "Selecciona una opción de DNS [1-6]: " dns_choice
	done

	case "${dns_choice}" in
	1)
		CLIENT_DNS_1="1.1.1.1"
		CLIENT_DNS_2="1.0.0.1"
		;;
	2)
		CLIENT_DNS_1="8.8.8.8"
		CLIENT_DNS_2="8.8.4.4"
		;;
	3)
		CLIENT_DNS_1="208.67.222.222"
		CLIENT_DNS_2="208.67.220.220"
		;;
	4)
		CLIENT_DNS_1="94.140.14.14"
		CLIENT_DNS_2="94.140.15.15"
		;;
	5)
		echo ""
		echo "Introduce tu(s) propio(s) servidor(es) DNS."
		until validateIp "${CLIENT_DNS_1}"; do
			read -rp "Primer resolvedor DNS: " -e CLIENT_DNS_1
			if ! validateIp "${CLIENT_DNS_1}"; then
				echo -e "${ORANGE}Dirección IP inválida. Por favor, introduce una dirección IPv4 o IPv6 válida.${NC}"
			fi
		done
		local use_second_dns
		read -rp "¿Deseas usar un segundo resolvedor DNS? [y/n]: " -e -i "n" use_second_dns
		if [[ ${use_second_dns} == "y" ]]; then
			until validateIp "${CLIENT_DNS_2}"; do
				read -rp "Segundo resolvedor DNS: " -e CLIENT_DNS_2
				if ! validateIp "${CLIENT_DNS_2}"; then
					echo -e "${ORANGE}Dirección IP inválida. Por favor, introduce una dirección IPv4 o IPv6 válida.${NC}"
				fi
			done
		else
			CLIENT_DNS_2="" # No se usará un segundo DNS si el usuario no lo desea
		fi
		;;
	6)
		CLIENT_DNS_1=""
		CLIENT_DNS_2=""
		echo -e "${ORANGE}No se configurarán resolvedores DNS para los clientes. Asegúrate de que los clientes tengan otros medios para resolver nombres de host.${NC}"
		;;
	esac
}

# configuraciones basicas, ip, puerto, dns, ips permitidas, name interfaces ethernet
function installQuestions() {
	echo "¡Bienvenido al instalador de WireGuard!"
	echo "El repositorio de git está disponible en: https://github.com/Cormaxs/wireguard-install-update-update"
	echo ""
	echo "Necesito hacerte algunas preguntas antes de iniciar la configuración."
	echo "Puedes mantener las opciones predeterminadas y simplemente presionar Enter si estás de acuerdo."
	echo ""

	# Detecta la dirección IP pública IPv4 o IPv6 y pre-rellena para el usuario
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1 || true)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detecta la dirección IP pública IPv6
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1 || true)
	fi
	read -rp "Dirección IP pública IPv4 o IPv6: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detecta la interfaz pública y pre-rellena para el usuario
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1 || true)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Interfaz pública: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "Nombre de la interfaz de WireGuard: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "IPv4 del servidor WireGuard: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "IPv6 del servidor WireGuard: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Genera un número aleatorio dentro del rango de puertos privados
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Puerto del servidor WireGuard [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Nueva selección de DNS
	showDnsOptions

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard usa un parámetro llamado AllowedIPs para determinar qué se enruta a través de la VPN."
		read -rp "Lista de IPs permitidas para los clientes generados (dejar por defecto para enrutar todo): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	echo ""
	echo "Bien, eso es todo lo que necesitaba. Estamos listos para configurar tu servidor WireGuard."
	echo "Podrás generar un cliente al final de la instalación."
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function installWireGuard() {
	# Ejecuta las preguntas de configuración primero
	installQuestions

	# Instala las herramientas y el módulo de WireGuard
	echo -e "${GREEN}Instalando WireGuard y dependencias...${NC}"
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -ge 10 ]]; then # Debian 10 Buster includes WireGuard in main
		apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then # For older Debian versions requiring backports
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update -qq
		fi
		DEBIAN_FRONTEND=noninteractive apt-get install -y iptables resolvconf qrencode
		DEBIAN_FRONTEND=noninteractive apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then # EPEL and kmod-wireguard are primarily for EL8
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
		fi
		# qrencode might not be available on EL9+ by default, but wireguard-tools should be.
		yum install -y wireguard-tools qrencode || true # qrencode might fail, make it non-fatal
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -Syu --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		apk add wireguard-tools iptables build-base libpng-dev
		# Handle qrencode compilation
		if ! command -v qrencode &>/dev/null; then
			echo -e "${ORANGE}Compiling qrencode from source...${NC}"
			curl -sO https://fukuchi.org/works/qrencode/qrencode-4.1.1.tar.gz
			tar xf qrencode-4.1.1.tar.gz
			(cd qrencode-4.1.1 && ./configure --prefix=/usr && make && make install && ldconfig)
		fi
	fi

	# Add check for installation success:
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}Error: WireGuard tools not found after installation attempt. Aborting.${NC}"
		exit 1
	fi

	# Asegura que el directorio exista y establece los permisos correctos
	mkdir -p /etc/wireguard
	chmod 700 /etc/wireguard/
	# Los permisos de los archivos .conf se establecen al crearlos/modificarlos individualmente.
	# No es necesario un chmod global aquí que podría fallar si el directorio está vacío.

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Guarda la configuración de WireGuard (parámetros)
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params
	# Establece permisos para el archivo de parámetros
	chmod 600 /etc/wireguard/params

	# Agrega la interfaz del servidor
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
MTU = 1420" >"/etc/wireguard/${SERVER_WG_NIC}.conf" # <-- OPTIMIZACIÓN: MTU para el servidor

	# Establece permisos para el archivo de configuración del servidor
	chmod 600 "/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/') # Asume un prefijo de 64 bits similar
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'
PostDown = firewall-cmd --zone=public --remove-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/64 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else # iptables
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
PostDown = ip6tables -D NAT -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf" # Fix for ip6tables NAT PostDown
	fi

	# Habilita el enrutamiento en el servidor
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

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
	echo -e "${GREEN}Si quieres añadir más clientes, ¡simplemente ejecuta este script otra vez!${NC}"

	# Verifica si WireGuard se está ejecutando
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status || true
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" || true
	fi
	WG_RUNNING=$?

	# WireGuard podría no funcionar si actualizamos el kernel. Avisa al usuario para que reinicie
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}ADVERTENCIA: WireGuard no parece estar en ejecución.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}Puedes comprobar si WireGuard está ejecutándose con: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}Puedes comprobar si WireGuard está ejecutándose con: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}Si obtienes algo como \"No se puede encontrar el dispositivo ${SERVER_WG_NIC}\", ¡por favor, reinicia!${NC}"
	else # WireGuard está en ejecución
		echo -e "\n${GREEN}WireGuard está en ejecución.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}Puedes comprobar el estado de WireGuard con: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}Puedes comprobar el estado de WireGuard con: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}Si no tienes conectividad a Internet desde tu cliente, intenta reiniciar el servidor.${NC}"
	fi
}

function newClient() {
	# Si SERVER_PUB_IP es IPv6, añade corchetes si faltan
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Configuración del cliente"
	echo ""
	echo "El nombre del cliente debe consistir en caracteres alfanuméricos. También puede incluir guiones bajos o guiones y no puede exceder los 15 caracteres."

	local CLIENT_EXISTS
	local CLIENT_NAME
	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Nombre del cliente: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}Ya se creó un cliente con el nombre especificado, por favor, elige otro nombre.${NC}"
			echo ""
			CLIENT_NAME="" # Limpia para forzar otra entrada
		fi
	done

	local DOT_EXISTS
	local DOT_IP
	for DOT_IP in {2..254}; do # Empieza desde 2 porque .1 es el servidor
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo -e "${RED}La subred configurada soporta solo 253 clientes. No se puede añadir más.${NC}"
		exit 1
	fi

	local BASE_IP
	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	local IPV4_EXISTS
	local CLIENT_WG_IPV4
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "IPv4 del cliente WireGuard: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}Ya se creó un cliente con la IPv4 especificada, por favor, elige otra IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	local IPV6_EXISTS
	local CLIENT_WG_IPV6
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "IPv6 del cliente WireGuard: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}Ya se creó un cliente con la IPv6 especificada, por favor, elige otra IPv6.${NC}"
			echo ""
		fi
	done

	# Genera el par de claves para el cliente
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Forma la cadena DNS para el archivo de configuración del cliente
	DNS_STRING=""
	if [[ -n "${CLIENT_DNS_1}" ]]; then
		DNS_STRING="DNS = ${CLIENT_DNS_1}"
		if [[ -n "${CLIENT_DNS_2}" ]]; then
			DNS_STRING="${DNS_STRING},${CLIENT_DNS_2}"
		fi
	fi

	# Crea el archivo del cliente y añade el servidor como par
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
MTU = 1420 # <-- OPTIMIZACIÓN: MTU para el cliente
${DNS_STRING}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Establece permisos para el archivo de configuración del cliente
	chmod 600 "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Añade el cliente como par al servidor
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Aplicar cambios a la configuración de WireGuard sin reiniciar el servicio
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Genera el código QR si qrencode está instalado
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nAquí está el archivo de configuración de tu cliente como Código QR:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Tu archivo de configuración de cliente está en ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo -e "${ORANGE}¡No tienes clientes existentes!${NC}"
		read -n1 -r -p "Presiona cualquier tecla para continuar..."
		return 0 # Usamos return en lugar de exit para volver al menú
	fi

	echo ""
	echo "Clientes WireGuard existentes:"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	echo ""
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function viewClientConfig() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo -e "${ORANGE}¡No tienes clientes existentes para ver!${NC}"
		read -n1 -r -p "Presiona cualquier tecla para continuar..."
		return
	fi

	echo ""
	echo "Selecciona el cliente cuya configuración deseas ver:"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	local CLIENT_NUMBER
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${NUMBER_OF_CLIENTS} == '1' ]]; then
			read -rp "Selecciona un cliente [1]: " CLIENT_NUMBER
		else
			read -rp "Selecciona un cliente [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	local CLIENT_CONFIG_FILE="${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	if [[ -f "${CLIENT_CONFIG_FILE}" ]]; then
		echo -e "${GREEN}\n--- Configuración de ${CLIENT_NAME} ---${NC}"
		cat "${CLIENT_CONFIG_FILE}"
		echo -e "${GREEN}-------------------------------------${NC}"

		if command -v qrencode &>/dev/null; then
			echo -e "${GREEN}\nCódigo QR para ${CLIENT_NAME}:\n${NC}"
			qrencode -t ansiutf8 -l L <"${CLIENT_CONFIG_FILE}"
			echo ""
		else
			echo -e "${ORANGE}qrencode no está instalado. No se puede generar el código QR.${NC}"
		fi
	else
		echo -e "${RED}Error: Archivo de configuración para ${CLIENT_NAME} no encontrado en ${CLIENT_CONFIG_FILE}.${NC}"
	fi
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo -e "${ORANGE}¡No tienes clientes existentes para revocar!${NC}"
		read -n1 -r -p "Presiona cualquier tecla para continuar..."
		return
	fi

	echo ""
	echo "Selecciona el cliente existente que deseas revocar"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	local CLIENT_NUMBER
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${NUMBER_OF_CLIENTS} == '1' ]]; then
			read -rp "Selecciona un cliente [1]: " CLIENT_NUMBER
		else
			read -rp "Selecciona un cliente [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# Coincide el número seleccionado con un nombre de cliente
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	echo -e "${ORANGE}Revocando cliente: ${CLIENT_NAME}...${NC}"

	# Elimina el bloque [Peer] que coincide con $CLIENT_NAME
	# sed -i utiliza un patrón para eliminar desde la línea "### Client CLIENT_NAME" hasta la siguiente línea vacía
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Elimina el archivo de cliente generado
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Reinicia wireguard para aplicar los cambios
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	echo -e "${GREEN}Cliente ${CLIENT_NAME} revocado exitosamente.${NC}"
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function enableDisableClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo -e "${ORANGE}¡No tienes clientes existentes para habilitar/deshabilitar!${NC}"
		read -n1 -r -p "Presiona cualquier tecla para continuar..."
		return
	fi

	echo ""
	echo "Selecciona el cliente que deseas habilitar/deshabilitar:"

	# Mostrar clientes y su estado (habilitado/deshabilitado)
	local i=1
	while read -r line; do
		local client_name=$(echo "$line" | cut -d ' ' -f 3)
		if grep -q -E "^### Client ${client_name}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
			if grep -q -E "^### Client ${client_name}\$\n#[Peer]" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
				echo "   ${i}) ${client_name} ${ORANGE}(Deshabilitado)${NC}"
			else
				echo "   ${i}) ${client_name} ${GREEN}(Habilitado)${NC}"
			fi
		fi
		i=$((i + 1))
	done < <(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")

	local CLIENT_NUMBER
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${NUMBER_OF_CLIENTS} == '1' ]]; then
			read -rp "Selecciona un cliente [1]: " CLIENT_NUMBER
		else
			read -rp "Selecciona un cliente [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	if grep -q -E "^### Client ${CLIENT_NAME}\$\n#[Peer]" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
		# Cliente está deshabilitado, lo habilitamos
		echo -e "${GREEN}Habilitando cliente: ${CLIENT_NAME}...${NC}"
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/{ s/^#\([A-Za-z]\)/#\1/; s/^#[Peer]/[Peer]/; s/^#PublicKey/PublicKey/; s/^#PresharedKey/PresharedKey/; s/^#AllowedIPs/AllowedIPs/; }" "/etc/wireguard/${SERVER_WG_NIC}.conf"
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ { /^\s*#/! s/^#// }" "/etc/wireguard/${SERVER_WG_NIC}.conf" # Intenta descomentar líneas que podrían estar comentadas
		sed -i "s/^#\([A-Za-z0-9_-]\)/\\1/" "/etc/wireguard/${SERVER_WG_NIC}.conf" # Uncomments lines starting with # followed by alphanumeric/underscore/hyphen
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ { s/^#\[Peer\]/\[Peer\]/; s/^#PublicKey/PublicKey/; s/^#PresharedKey/PresharedKey/; s/^#AllowedIPs/AllowedIPs/; }" "/etc/wireguard/${SERVER_WG_NIC}.conf"

		# Eliminar líneas que solo tienen un '#' (artefactos de un posible doble comentado)
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ { /^#/!s/^#//; /^##/d }" "/etc/wireguard/${SERVER_WG_NIC}.conf"
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ { s/^##/#/ }" "/etc/wireguard/${SERVER_WG_NIC}.conf"

		# Re-comentar la línea ### Client si está descomentada
		sed -i "/^### Client ${CLIENT_NAME}\$/!b;N;s/^### Client \(.*\)\n\[Peer\]/### Client \1\n[Peer]/" "/etc/wireguard/${SERVER_WG_NIC}.conf"

		echo -e "${GREEN}Cliente ${CLIENT_NAME} habilitado exitosamente.${NC}"
	else
		# Cliente está habilitado, lo deshabilitamos
		echo -e "${ORANGE}Deshabilitando cliente: ${CLIENT_NAME}...${NC}"
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/{ s/^#\([A-Za-z]\)/#\1/; s/^\[Peer\]/#\[Peer\]/; s/^PublicKey/#PublicKey/; s/^PresharedKey/#PresharedKey/; s/^AllowedIPs/#AllowedIPs/; }" "/etc/wireguard/${SERVER_WG_NIC}.conf"
		sed -i "s/^### Client \(.*\)/### Client \1\n#/" "/etc/wireguard/${SERVER_WG_NIC}.conf" # Add a dummy commented line to fix previous sed issue
		sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/ { s/^\(\[Peer\]\)/#\1/; s/^\(PublicKey\)/#\1/; s/^\(PresharedKey\)/#\1/; s/^\(AllowedIPs\)/#\1/; }" "/etc/wireguard/${SERVER_WG_NIC}.conf"
		echo -e "${ORANGE}Cliente ${CLIENT_NAME} deshabilitado exitosamente.${NC}"
	fi

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}


function showServerInfo() {
	echo -e "${GREEN}\n--- Información del Servidor WireGuard ---${NC}"
	echo "Interfaz WireGuard: ${SERVER_WG_NIC}"
	echo "IP pública del servidor: ${SERVER_PUB_IP}"
	echo "Puerto de escucha: ${SERVER_PORT}/udp"
	echo "IPs del servidor en la VPN: ${SERVER_WG_IPV4}/24, ${SERVER_WG_IPV6}/64"
	echo "Clave pública del servidor: ${SERVER_PUB_KEY}"
	echo "DNS de clientes (predeterminado): ${CLIENT_DNS_1} ${CLIENT_DNS_2}"
	echo "IPs permitidas para clientes (predeterminado): ${ALLOWED_IPS}"

	echo ""
	echo "Estado del servicio WireGuard:"
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" status || echo -e "${ORANGE}No se pudo obtener el estado del servicio.${NC}"
	else
		systemctl status "wg-quick@${SERVER_WG_NIC}" --no-pager || echo -e "${ORANGE}No se pudo obtener el estado del servicio.${NC}"
	fi
	echo ""
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function viewCurrentWgStatus() {
	echo -e "${GREEN}\n--- Estado Actual de WireGuard (${SERVER_WG_NIC}) ---${NC}"
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}Error: Las herramientas de WireGuard (wg) no están instaladas.${NC}"
		echo -e "${ORANGE}Por favor, reinstala WireGuard o verifica la instalación.${NC}"
		read -n1 -r -p "Presiona cualquier tecla para continuar..."
		return
	fi

	if ! wg show "${SERVER_WG_NIC}" &>/dev/null; then
		echo -e "${ORANGE}La interfaz WireGuard '${SERVER_WG_NIC}' no está activa o no existe.${NC}"
		echo -e "${ORANGE}Asegúrate de que el servicio 'wg-quick@${SERVER_WG_NIC}' esté ejecutándose.${NC}"
	else
		wg show "${SERVER_WG_NIC}"
	fi
	echo ""
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function changeServerPort() {
	echo -e "${GREEN}\n--- Cambiar Puerto del Servidor WireGuard ---${NC}"
	local NEW_PORT
	local OLD_PORT=${SERVER_PORT}

	until [[ ${NEW_PORT} =~ ^[0-9]+$ ]] && [ "${NEW_PORT}" -ge 1 ] && [ "${NEW_PORT}" -le 65535 ]; do
		read -rp "Introduce el nuevo puerto para WireGuard [1-65535]: " -e -i "${RANDOM_PORT}" NEW_PORT
		if [ "${NEW_PORT}" == "${OLD_PORT}" ]; then
			echo -e "${ORANGE}El nuevo puerto es el mismo que el actual. No se realizarán cambios.${NC}"
			read -n1 -r -p "Presiona cualquier tecla para continuar..."
			return
		fi
	done

	echo -e "${ORANGE}Cambiando el puerto del servidor de ${OLD_PORT} a ${NEW_PORT}...${NC}"

	# Actualizar el archivo de parámetros
	sed -i "s/^SERVER_PORT=${OLD_PORT}/SERVER_PORT=${NEW_PORT}/" /etc/wireguard/params
	SERVER_PORT=${NEW_PORT} # Actualizar la variable en el script

	# Actualizar el archivo de configuración del servidor
	sed -i "s/^ListenPort = ${OLD_PORT}/ListenPort = ${NEW_PORT}/" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Actualizar reglas de firewall
	if pgrep firewalld; then
		firewall-cmd --remove-port="${OLD_PORT}"/udp --permanent || true
		firewall-cmd --add-port="${NEW_PORT}"/udp --permanent
		firewall-cmd --reload
	else # iptables
		# Eliminar reglas antiguas y añadir nuevas para el puerto
		# Nota: Esto es más robusto si se elimina la línea del PostUp original y se reinserta.
		# Para simplificar y evitar problemas con múltiples PostUp, aquí se asume que solo hay una línea de puerto.
		# Una solución más robusta podría implicar reescribir todo el bloque PostUp/PostDown.
		sed -i "s/PostUp = iptables -I INPUT -p udp --dport ${OLD_PORT} -j ACCEPT/PostUp = iptables -I INPUT -p udp --dport ${NEW_PORT} -j ACCEPT/" "/etc/wireguard/${SERVER_WG_NIC}.conf"
		sed -i "s/PostDown = iptables -D INPUT -p udp --dport ${OLD_PORT} -j ACCEPT/PostDown = iptables -D INPUT -p udp --dport ${NEW_PORT} -j ACCEPT/" "/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Reiniciar WireGuard para aplicar los cambios
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" restart
	else
		systemctl restart "wg-quick@${SERVER_WG_NIC}"
	fi

	echo -e "${GREEN}Puerto del servidor WireGuard cambiado a ${NEW_PORT} exitosamente.${NC}"
	echo -e "${ORANGE}¡Recuerda que tus clientes existentes necesitarán actualizar su configuración de Endpoint para conectarse al nuevo puerto!${NC}"
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function backupConfiguration() {
	echo -e "${GREEN}\n--- Copia de Seguridad de la Configuración de WireGuard ---${NC}"
	local BACKUP_DIR="/root/wireguard_backups"
	local TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
	local BACKUP_FILE="${BACKUP_DIR}/wireguard_config_backup_${TIMESTAMP}.tar.gz"

	mkdir -p "${BACKUP_DIR}"
	chmod 700 "${BACKUP_DIR}" # Asegura que solo root pueda ver las copias de seguridad

	echo -e "${ORANGE}Creando copia de seguridad de /etc/wireguard en ${BACKUP_FILE}...${NC}"

	if tar -czf "${BACKUP_FILE}" "/etc/wireguard"; then
		echo -e "${GREEN}Copia de seguridad creada exitosamente en: ${BACKUP_FILE}${NC}"
		echo "Para restaurar, puedes usar: tar -xzf ${BACKUP_FILE} -C /"
	else
		echo -e "${RED}Error: Falló la creación de la copia de seguridad.${NC}"
	fi
	read -n1 -r -p "Presiona cualquier tecla para continuar..."
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}ADVERTENCIA: ¡Esto desinstalará WireGuard y eliminará todos los archivos de configuración!${NC}"
	echo -e "${ORANGE}Por favor, haz una copia de seguridad del directorio /etc/wireguard si quieres conservar tus archivos de configuración.\n${NC}"
	local REMOVE
	read -rp "¿Realmente quieres eliminar WireGuard? [y/n]: " -e -i "n" REMOVE
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		echo -e "${ORANGE}Deteniendo y deshabilitando el servicio WireGuard...${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop || true
			rc-update del "wg-quick.${SERVER_WG_NIC}" || true
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}" || true
			rc-update del sysctl || true
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}" || true
			systemctl disable "wg-quick@${SERVER_WG_NIC}" || true
		fi

		echo -e "${ORANGE}Eliminando paquetes de WireGuard y dependencias...${NC}"
		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
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
			(cd qrencode-4.1.1 || true && make uninstall) || true # Intenta desinstalar si se compiló
			rm -rf qrencode-* || true                             # Limpia archivos de compilación si existen
			apk del wireguard-tools build-base libpng-dev
		fi

		echo -e "${ORANGE}Limpiando archivos de configuración...${NC}"
		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf
		rm -f "${TARGET_INSTALL_PATH}" # Elimina el script de auto-instalación

		if [[ ${OS} != 'alpine' ]]; then
			sysctl --system # Recarga sysctl para asegurar que el reenvío esté deshabilitado si no hay otros ajustes.
		fi

		# Verifica si WireGuard se está ejecutando (debería fallar si la desinstalación fue exitosa)
		local WG_RUNNING_AFTER_UNINSTALL=0
		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null && WG_RUNNING_AFTER_UNINSTALL=1 || true
		else
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}" &>/dev/null && WG_RUNNING_AFTER_UNINSTALL=1 || true
		fi

		if [[ ${WG_RUNNING_AFTER_UNINSTALL} -eq 1 ]]; then
			echo -e "${RED}WireGuard falló al desinstalarse completamente. Puede que necesites una limpieza manual.${NC}"
			exit 1
		else
			echo -e "${GREEN}WireGuard desinstalado exitosamente.${NC}"
			exit 0
		fi
	else
		echo ""
		echo -e "${GREEN}¡Eliminación abortada!${NC}"
	fi
}

function manageMenu() {
	echo -e "${GREEN}¡Bienvenido a WireGuard-install!${NC}"
	echo "El repositorio de git está disponible en: https://github.com/Cormaxs/wireguard-install-update"
	echo ""
	echo "Parece que WireGuard ya está instalado."
	echo ""
	echo "¿Qué quieres hacer?"
	echo "--- Gestión de Clientes ---"
	echo "   1) Añadir un nuevo cliente"
	echo "   2) Listar todos los clientes"
	echo "   3) Ver configuración de un cliente" # Nueva
	echo "   4) Revocar un cliente existente"
	echo "   5) Habilitar/Deshabilitar un cliente" # Nueva
	echo "--- Información y Diagnóstico ---"
	echo "   6) Mostrar información del servidor" # Nueva
	echo "   7) Ver estado actual de WireGuard" # Nueva
	echo "--- Configuración del Servidor ---"
	echo "   8) Cambiar puerto del servidor" # Nueva
	echo "--- Utilidades ---"
	echo "   9) Hacer copia de seguridad de la configuración" # Nueva
	echo "   10) Desinstalar WireGuard"
	echo "   11) Salir"
	local MENU_OPTION
	until [[ ${MENU_OPTION} =~ ^(1[0-1]|[1-9])$ ]]; do
		read -rp "Selecciona una opción [1-11]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		viewClientConfig
		;;
	4)
		revokeClient
		;;
	5)
		enableDisableClient
		;;
	6)
		showServerInfo
		;;
	7)
		viewCurrentWgStatus
		;;
	8)
		changeServerPort
		;;
	9)
		backupConfiguration
		;;
	10)
		uninstallWg
		;;
	11)
		echo -e "${GREEN}Saliendo... ¡Hasta pronto!${NC}"
		exit 0
		;;
	esac
}

# Verificaciones iniciales (root, virtualización, SO)
# Estas se ejecutan después de la auto-instalación si es necesario,
# o directamente si el script ya está instalado como 'wg-menu'.
initialCheck

# Carga los parámetros de WireGuard si ya está instalado
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	# Verificar si SERVER_WG_NIC está definido después de cargar params
	if [[ -z "${SERVER_WG_NIC}" ]]; then
		echo -e "${RED}Error: La interfaz de WireGuard no se encontró en /etc/wireguard/params. Reinstalación recomendada.${NC}"
		exit 1
	fi
	manageMenu
else
	installWireGuard
fi