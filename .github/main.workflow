workflow "ShellCheck" {
  on = "push"
  resolves = ["shellcheck"]
}

action "shellcheck" {
  uses = "ludeeus/actions/shellcheck@master"
}
