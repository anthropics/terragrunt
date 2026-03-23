terraform {
  extra_arguments "canary" {
    commands = ["init", "plan", "apply", "validate"]
    env_vars = { TF_VAR_canary = "EXTRA_ARGS_LEAKED" }
  }
}
