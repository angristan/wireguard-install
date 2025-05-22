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
	if ! command -v wg-menu &>/dev/null || [[ "$(readlink -f "$(command -v wg-menu 2>/dev/null || true)")" != "${TARGET_INSTALL_PATH}" ]]; then
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

function checkVirt() {
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
	if command -v virt-what &>/dev/null; then
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

	if [ -z "${CLIENT_NAME}" ]; then
		echo -e "${RED}Error: getHomeDirForClient() requiere un nombre de cliente como argumento.${NC}"
		exit 1
	fi

	# Directorio de inicio del usuario, donde se escribirá la configuración del cliente
	if [ -e "/home/${CLIENT_NAME}" ] && [ -d "/home/${CLIENT_NAME}" ]; then
		# si $1 es un nombre de usuario existente con un directorio home
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# si no, usa SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# Si se ejecuta sudo como root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# si no es SUDO_USER, usa /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
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
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		apk add wireguard-tools iptables build-base libpng-dev
		# Construye qrencode desde la fuente ya que no está fácilmente disponible como paquete
		curl -O https://fukuchi.org/works/qrencode/qrencode-4.1.1.tar.gz
		tar xf qrencode-4.1.1.tar.gz
		(cd qrencode-4.1.1 && ./configure && make && make install && ldconfig)
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
MTU = 1420
# OPTIMIZACIÓN: Mantener el túnel activo para reducir latencia inicial
PersistentKeepalive = 25" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

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
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Habilita el enrutamiento en el servidor y añade optimizaciones del kernel
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# OPTIMIZACIÓN: Buffers de red para mejor rendimiento en alta velocidad
net.core.rmem_default = 262144
net.core.rmem_max = 8388608
net.core.wmem_default = 262144
net.core.wmem_max = 8388608
# OPTIMIZACIÓN: Habilitar BBR para mejor control de congestión
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system # Aplica los cambios de sysctl inmediatamente

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
MTU = 1420
# OPTIMIZACIÓN: Mantener el túnel activo para reducir latencia inicial
PersistentKeepalive = 25
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
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "¡No tienes clientes existentes!"
		exit 0 # Salir sin error si no hay clientes
	fi

	echo ""
	echo "Clientes WireGuard existentes:"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || true)
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "¡No tienes clientes existentes!"
		exit 0 # Salir sin error si no hay clientes
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
	echo "   1) Añadir un nuevo usuario"
	echo "   2) Listar todos los usuarios"
	echo "   3) Revocar un usuario existente"
	echo "   4) Desinstalar WireGuard"
	echo "   5) Salir"
	local MENU_OPTION
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Selecciona una opción [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
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
