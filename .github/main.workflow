workflow "ShellCheck" {
  on = "push"
  resolves = ["shellcheck"]
}

action "shellcheck" {
  uses = "actions/bin/shellcheck@master"
  args = "wireguard-install.sh -e SC1091 -e SC2034"
}
