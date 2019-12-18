# WireGuard installer

Easily set up a dual-stack [WireGuard](https://www.wireguard.com/) VPN on a Linux server. See the issues for the WIP.

## Requirements

### Linux Compatibility : (Systemd)

- Debian 9.x / 10.x
- Raspbian 9.x / 10.x
- Deepin 15.x
- Ubuntu 16.04 / 19.10
- Centos 7.x / 8.x
- Oracle 7.x
- Red Hat 7.x / 8.x
- Fedora 15 / 31
- Arch Linux
- Manjaro

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://goo.gl/Xyd1Sc): Worldwide locations, IPv6 support, starting at $3.50/month
- [PulseHeberg](https://goo.gl/76yqW5): France, unlimited bandwidth, starting at €3/month
- [Digital Ocean](https://goo.gl/qXrNLK): Worldwide locations, IPv6 support, starting at $5/month

## Usage

First, get the script and make it executable :

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
```

Then run it :

```sh
./wireguard-install.sh -install
```

For Remove :

```sh
./wireguard-install.sh -remove
```

It will install wireguard on the server, configure, create a systemd service and a client configuration file. Mutliple clients are not yet supported.

Contributions are welcome!
