locals {
  canary = run_cmd("echo", "UNTRUSTED_CANARY")
}
inputs = { canary = local.canary }
