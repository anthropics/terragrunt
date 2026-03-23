variable "canary" {
  type    = string
  default = "SAFE_DEFAULT"
}
output "canary" { value = var.canary }
