# WireGuard installer

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN on a Linux server, as easily as possible!**

WireGuard is a point-to-point VPN that can be used in different ways. Here, we mean a VPN as in: the client will forward all its traffic trough an encrypted tunnel to the server.
The server will apply NAT to the client's traffic so it will appear as if the client is browsing the web with the server's IP.

The script supports both IPv4 and IPv6. Please check the [issues](https://github.com/angristan/wireguard-install/issues) for ongoing development, bugs and planned features!

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/angristan/openvpn-install).

## Requirements

Supported distributions:

- Ubuntu >= 16.04
- Debian 10
- Fedora
- CentOS
- Arch Linux

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients!

## Headless install

It's also possible to run the script headless, e.g. without waiting for user input, in an automated manner.

Example usage:

```bash
AUTO_INSTALL=y ./wireguard-install.sh

# or

export AUTO_INSTALL=y
./wireguard-install.sh
```

A default set of variables will then be set, by passing the need for user input.

If you want to customise your installation, you can export them or specify them on the same line, as shown above.

- `APPROVE_INSTALL=y`
- `APPROVE_IP=y`
- `APPROVE_NIC=y`
- `SERVER_WG_NIC=wg0`
- `SERVER_WG_IPV4=10.66.66.1`
- `SERVER_WG_IPV6=fd42:42:42::1`
- `SERVER_PORT=51820`
- `CLIENT_DNS_1=176.103.130.130`
- `CLIENT_DNS_2=176.103.130.131`
- `CLIENT_NAME=client`
- `CLIENT_DOT_IPV4=2`
- `CLIENT_DOT_IPV6=2`

If the server is behind NAT, you can specify its endpoint with the `SERVER_PUB_IP` variable. If the endpoint is the public IP address which it is behind, you can use `SERVER_PUB_IP=$(curl ifconfig.co)` (the script will default to this). The endpoint can be an IP or a domain.

Other variables can be set depending on your choice (`SERVER_NIC`). You can search for them in the `installQuestions()` function of the script.

## Headless User Addition

It's also possible to automate the addition of a new user. Here, the key is to provide the (string) value of the `MENU_OPTION` variable along with the remaining mandatory variables before invoking the script.

The following Bash script adds a new user `foo` to an existing WireGuard configuration

```bash
#!/bin/bash
export MENU_OPTION="1"
export CLIENT_NAME="foo"
export CLIENT_DOT_IPV4="3"
export CLIENT_DOT_IPV6="3"
./wireguard-install.sh
```

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://goo.gl/Xyd1Sc): Worldwide locations, IPv6 support, starting at \$3.50/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, IPv6, 20 TB of traffic, starting at €3/month
- [Digital Ocean](https://goo.gl/qXrNLK): Worldwide locations, IPv6 support, starting at \$5/month
- [PulseHeberg](https://goo.gl/76yqW5): France, unlimited bandwidth, starting at €3/month
