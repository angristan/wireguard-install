# Instalador de WireGuard

![Lint](https://github.com/Cormaxs/wireguard-install/workflows/Lint/badge.svg)

**Este proyecto es un script bash que busca configurar una VPN [WireGuard](https://www.wireguard.com/) en un servidor Linux de la forma más sencilla posible.**

WireGuard es una VPN punto a punto que puede usarse de diferentes maneras. En este contexto, nos referimos a una VPN como: el cliente reenvía todo su tráfico al servidor a través de un túnel cifrado.
El servidor aplica NAT al tráfico del cliente, de modo que parecerá que este navega por la web con la IP del servidor.

El script es compatible con IPv4 e IPv6.

¿WireGuard no se adapta a tu entorno? Consulta [openvpn-install](https://github.com/angristan/openvpn-install).

## Requisitos

Distribuciones compatibles:

- AlmaLinux >= 8
- Alpine Linux
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Como usar

Dentro de tu vps pega el comando siguiente, luego anda confirmando los datos de las opciones.

```bash
curl -O https://raw.githubusercontent.com/Cormaxs/wireguard-install-update/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

Instalará WireGuard (módulo del kernel y herramientas) en el servidor, lo configurará, creará un servicio systemd y un archivo de configuración de cliente.

Para ver el menu ejecutar

```bash
wg-menu
```

## Proveedores

Recomiendo estos proveedores de nube económicos para tu servidor VPN:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Ubicaciones en todo el mundo, compatibilidad con IPv6, desde $5 al mes
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Alemania, Finlandia y EE. UU. IPv6, 20 TB de tráfico, desde $4,5 al mes
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Ubicaciones en todo el mundo, compatibilidad con IPv6, desde $4 al mes
- [Dartnode](https://dartnode.com/vps/1/configure): EE. UU, compatibilidad con IPv6, desde $2 al mes
- [Bluehosting](https://panel.bluehosting.host/cart.php?a=confproduct&i=0): chile, compatibilidad con IPv6, desde $1,5 al mes

## Créditos y licencia

Este proyecto está bajo la [Licencia MIT](https://raw.githubusercontent.com/angristan/wireguard-install/master/LICENSE)
