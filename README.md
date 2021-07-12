# WireGuard installer

![Lint](https://github.com/angristan/wireguard-install/workflows/Lint/badge.svg)
![visitors](https://visitor-badge.glitch.me/badge?page_id=angristan.wireguard-install)

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

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://goo.gl/Xyd1Sc): Worldwide locations, IPv6 support, starting at \$3.50/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany and Finland, IPv6, 20 TB of traffic, starting at €3/month
- [Digital Ocean](https://goo.gl/qXrNLK): Worldwide locations, IPv6 support, starting at \$5/month
- [PulseHeberg](https://goo.gl/76yqW5): France, unlimited bandwidth, starting at €3/month

## Reference

- [YouTube](https://youtu.be/IEb1U6V1s3A): How To Setup WireGuard Virtual Private Network
