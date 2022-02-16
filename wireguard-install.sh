#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

WARN='\033[1;36m'
BOLD='\033[1;37m'
RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "{WARN}Вам нужно запустить этот скрипт от имени root-пользователя{NC}"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "{WARN}OpenVZ не поддерживается{NC}"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "{BOLD}LXC не поддерживается (пока).{NC}"
		echo "{BOLD}Технически WireGuard может работать в контейнере LXC,{NC}"
		echo "{BOLD}но модуль ядра должен быть установлен на хосте,{NC}"
		echo "{BOLD}контейнер должен быть запущен с некоторыми определенными параметрами{NC}"
		echo "{BOLD}и только инструменты должны быть установлены в контейнер.{NC}"
		exit 1
	fi
}

function checkOS() {
	# Проверка операционной системы
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS="${ID}" # debian or ubuntu
		if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
			if [[ ${VERSION_ID} -lt 10 ]]; then
				echo "Ваша версия Debian (${VERSION_ID}) не поддерживается. Пожалуйста, используйте Debian 10 Buster или более позднюю версию"
				exit 1
			fi
			OS=debian # overwrite if raspbian
		fi
	elif [[ -e /etc/fedora-release ]]; then
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		source /etc/os-release
		OS=centos
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "{BOLD}Похоже, вы не запускаете этот установщик в системе Debian, Ubuntu, Fedora, CentOS, Oracle или Arch Linux{NC}"
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function installQuestions() {
	echo "{BOLD}Добро пожаловать в WireGuard installer!{NC}"
	echo "{BOLD}Репозиторий git доступен по адресу: https://github.com/Romanoidz/wireguard-install{NC}"
	echo ""
	echo "{BOLD}Мне нужно задать вам несколько вопросов, прежде чем приступить к настройке.{NC}"
	echo "{BOLD}Вы можете оставить параметры по умолчанию и просто нажать Enter, если они вас устраивают.{NC}"
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "{BOLD}Публичный адрес IPv4 или IPv6: {NC}" -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Общедоступный интерфейс: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "Имя интерфейса WireGuard: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Адрес сервера WireGuard IPv4: " -e -i 192.168.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Адрес сервера WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Порт сервера WireGuard [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Yandex DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "1-й DNS-сервер, используемый для клиентов: " -e -i 77.88.8.8 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "2-й DNS-сервер, используемый для клиентов: (опционально): " -e -i 77.88.8.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	echo ""
	echo "Необходимые данные получены. Теперь можно настроить ваш сервер WireGuard."
	echo "Настроить и создать Клиента можно в конце установки."
	read -n1 -r -p "Нажмите любую клавишу, чтобы продолжить..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
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
	elif [[ ${OS} == 'centos' ]]; then
		yum -y install epel-release elrepo-release
		if [[ ${VERSION_ID} -eq 7 ]]; then
			yum -y install yum-plugin-elrepo
		fi
		yum -y install kmod-wireguard wireguard-tools iptables qrencode
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
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

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	newClient
	echo "Если вы хотите добавить больше клиентов, вам просто нужно запустить этот скрипт в еще раз!"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}ПРЕДУПРЕЖДЕНИЕ: WireGuard, похоже, не работает.${NC}"
		echo -e "${ORANGE}Вы можете проверить, работает ли WireGuard: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}Если вы получите что-то вроде \"Cannot find device ${SERVER_WG_NIC}\", пожалуйста, перезагрузитесь!${NC}"
	fi
}

function newClient() {
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Введите имя клиента."
	echo "Имя должно состоять из буквенно-цифровых символов. Оно также может содержать подчеркивание или тире и не может превышать 15 символов."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Имя клиента: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
			echo ""
			echo "Клиент с указанным именем уже создан, пожалуйста, выберите другое имя."
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "Настроенная подсеть поддерживает только 253 клиента."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Клиент WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/24" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} == '1' ]]; then
			echo ""
			echo "Клиент с указанным IPv4 уже создан, пожалуйста, выберите другой IPv4."
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Клиент WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/64" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} == '1' ]]; then
			echo ""
			echo "Клиент с указанным IPv6 уже создан, пожалуйста, выберите другой IPv6."
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

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

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0,::/0" >>"${HOME_DIR}/${SERVER_WG_NIC}-${SERVER_PUB_IP}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	echo -e "\nВот файл конфигурации вашего клиента в виде QR-кода:"

	qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-${SERVER_PUB_IP}-client-${CLIENT_NAME}.conf"

	echo "Он также доступен в ${HOME_DIR}/${SERVER_WG_NIC}-${SERVER_PUB_IP}-client-${CLIENT_NAME}.conf"
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "У вас нет существующих клиентов!"
		exit 1
	fi

	echo ""
	echo "Выберите существующего клиента, которого вы хотите отозвать"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Выберите одного клиента [1]: " CLIENT_NUMBER
		else
			read -rp "Выберите одного клиента [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	rm -f "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	read -rp "Вы действительно хотите удалить WireGuard? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "wg-quick@${SERVER_WG_NIC}"
		systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get autoremove --purge -y wireguard qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get autoremove --purge -y wireguard qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
			dnf autoremove -y
		elif [[ ${OS} == 'centos' ]]; then
			yum -y remove kmod-wireguard wireguard-tools qrencode
			yum -y autoremove
		elif [[ ${OS} == 'oracle' ]]; then
			yum -y remove wireguard-tools qrencode
			yum -y autoremove
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		# Reload sysctl
		sysctl --system

		# Check if WireGuard is running
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard не удалась удалить должным образом."
			exit 1
		else
			echo "WireGuard успешно удален"
			exit 0
		fi
	else
		echo ""
		echo "Удаление прервано!"
	fi
}

function manageMenu() {
	echo "Добро пожаловать в установку WireGuard-сервера!"
	echo "Репозиторий git доступен по адресу: https://github.com/Romanoidz/wireguard-install"
	echo ""
	echo "Похоже WireGuard уже установлен."
	echo ""
	echo "Что хотите сделать?"
	echo "   1) Добавить нового пользователя"
	echo "   2) Отозвать существующего пользователя"
	echo "   3) Удалить WireGuard"
	echo "   4) Выйти"
	until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
		read -rp "Выберите опцию [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		uninstallWg
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi
