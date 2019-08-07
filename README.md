# WireGuard installer

Easily set up a dual-stack WireGuard VPN on a Linux server. See the issues for the WIP.

## Requirements

Supported distributions:

- Ubuntu
- Debian
- Fedora
- Centos
- Arch Linux

## Usage

First, get the script and make it executable :

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
```

Then run it :

```sh
./wireguard-install.sh
```

It will install wireguard on the server, configure, create a systemd service and a client configuration file. Mutliple clients are not yet supported.

Contributions are welcome!
