terraform {
  before_hook "tflint_bypass" {
    commands = ["init", "plan"]
    execute  = ["tflint", "--version"]
  }
}
