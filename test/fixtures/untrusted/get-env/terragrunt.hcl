locals {
  leaked = get_env("UNTRUSTED_SECRET_ENV", "default")
}
inputs = { leaked = local.leaked }
