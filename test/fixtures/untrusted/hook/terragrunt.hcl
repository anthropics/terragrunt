terraform {
  before_hook "canary" {
    commands = ["init", "plan", "apply"]
    execute  = ["echo", "UNTRUSTED_HOOK_CANARY"]
  }
}
