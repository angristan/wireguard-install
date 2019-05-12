workflow "ShellCheck" {
  on = "push"
  resolves = ["ShellCheck"]
}

action "ShellCheck" {
  uses = "actions/bin/shellcheck@master"
  args = "wireguard-install.sh"
}
