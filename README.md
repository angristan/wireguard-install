# WireGuard installer

![Lint](https://github.com/angristan/wireguard-install/workflows/Lint/badge.svg)
[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/angristan)

**This project is a bash script that aims to setup a [WireGuard](https://www.wireguard.com/) VPN on a Linux server, as easily as possible!**

WireGuard is a point-to-point VPN that can be used in different ways. Here, we mean a VPN as in: the client will forward all its traffic through an encrypted tunnel to the server.
The server will apply NAT to the client's traffic so it will appear as if the client is browsing the web with the server's IP.

The script supports both IPv4 and IPv6. Please check the [issues](https://github.com/angristan/wireguard-install/issues) for ongoing development, bugs and planned features! You might also want to check the [discussions](https://github.com/angristan/wireguard-install/discussions) for help.

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/angristan/openvpn-install).

## Requirements

Supported distributions:

- AlmaLinux >= 8
- Alpine Linux
- Amazon Linux 2023
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- openSUSE Leap >= 15 and Tumbleweed
- Oracle Linux
- RHEL-compatible distributions >= 8
- Rocky Linux >= 8
- Ubuntu >= 18.04

## Usage

Download and execute the script. Answer the questions asked by the script and it will take care of the rest.

```bash
curl -O https://raw.githubusercontent.com/angristan/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

It will install WireGuard (kernel module and tools) on the server, configure it, create a systemd service and a client configuration file.

Run the script again to add or remove clients. You can also use the subcommand interface:

```bash
./wireguard-install.sh install --endpoint vpn.example.com --client alice
./wireguard-install.sh client add bob --output /tmp/bob.conf
./wireguard-install.sh client list
./wireguard-install.sh client revoke bob --force
./wireguard-install.sh server status
```

## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Worldwide locations, IPv6 support, starting at \$5/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, Finland and USA. IPv6, 20 TB of traffic, starting at 4.5€/month
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Worldwide locations, IPv6 support, starting at \$4/month

## Contributing

Contributions are welcome! Here's how you can help:

### Testing

Run the local test suite before opening a PR:

```bash
bash test/run-tests.sh
```

To run the Docker E2E test, you need Docker and WireGuard kernel support on the host:

```bash
bash test/e2e/run-docker-e2e.sh
```

Run it against another server base image with:

```bash
SERVER_BASE_IMAGE=debian:12 bash test/e2e/run-docker-e2e.sh
```

The GitHub Actions E2E matrix runs this across the supported distro families, plus focused nftables and dual-stack scenarios. You can run those locally with:

```bash
ENABLE_NFTABLES=y SERVER_BASE_IMAGE=debian:12 bash test/e2e/run-docker-e2e.sh
CLIENT_IPV6=y bash test/e2e/run-docker-e2e.sh
```

### Discuss changes

Please open an issue before submitting a PR if you want to discuss a change, especially if it's a big one.

### Code formatting

We use [shellcheck](https://github.com/koalaman/shellcheck) and [shfmt](https://github.com/mvdan/sh) to enforce bash styling guidelines and good practices. They are executed for each commit / PR with GitHub Actions, so you can check the configuration [here](https://github.com/angristan/wireguard-install/blob/master/.github/workflows/lint.yml).

## Say thanks

You can [say thanks](https://saythanks.io/to/angristan) if you want!

## Credits & Licence

This project is under the [MIT Licence](https://raw.githubusercontent.com/angristan/wireguard-install/master/LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=angristan/wireguard-install&type=Date)](https://star-history.com/#angristan/wireguard-install&Date)
