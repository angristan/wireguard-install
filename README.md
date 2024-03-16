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
- Arch Linux
- CentOS Stream >= 8
- Debian >= 10
- Fedora >= 32
- Oracle Linux
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

Run the script again to add or remove clients!

## Headless installation

It's also possible to run the script headless, e.g. without waiting for user input, in an automated way.

Example usage:

```bash
APPROVE_INSTALL=y ./wireguard-install.sh

# or

export APPROVE_INSTALL=y
./wireguard-install.sh
```

This will set a default set of variables, bypassing any user input.

If you want to customise your installation, you can use variables, as shown below:

```
export APPROVE_INSTALL=y
export SERVER_PUB_IP="54.14.1.48"
export SERVER_PORT=64567
export CLIENT_NAME=client
```

If the server is behind NAT, you can specify its endpoint with the `SERVER_PUB_IP` variable. If the endpoint is the public IP address which it is behind, you can use `SERVER_PUB_IP=$(curl -s https://api.ipify.org)` (the script defaults to this). The endpoint can be an IP or a domain.

The headless installation involves adding a new user. Adding `CLIENT_NAME=foo` will change the name of the new user to `foo` instead of the default.

Other variables can be set as required on your choice (`SERVER_NIC`). You can find them in the `installQuestions()` function of the script.


## Providers

I recommend these cheap cloud providers for your VPN server:

- [Vultr](https://www.vultr.com/?ref=8948982-8H): Worldwide locations, IPv6 support, starting at \$5/month
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Germany, Finland and USA. IPv6, 20 TB of traffic, starting at 4.5€/month
- [Digital Ocean](https://m.do.co/c/ed0ba143fe53): Worldwide locations, IPv6 support, starting at \$4/month

## Contributing

## Discuss changes

Please open an issue before submitting a PR if you want to discuss a change, especially if it's a big one.

### Code formatting

We use [shellcheck](https://github.com/koalaman/shellcheck) and [shfmt](https://github.com/mvdan/sh) to enforce bash styling guidelines and good practices. They are executed for each commit / PR with GitHub Actions, so you can check the configuration [here](https://github.com/angristan/wireguard-install/blob/master/.github/workflows/lint.yml).

## Say thanks

You can [say thanks](https://saythanks.io/to/angristan) if you want!

## Credits & Licence

This project is under the [MIT Licence](https://raw.githubusercontent.com/angristan/wireguard-install/master/LICENSE)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=angristan/wireguard-install&type=Date)](https://star-history.com/#angristan/wireguard-install&Date)
