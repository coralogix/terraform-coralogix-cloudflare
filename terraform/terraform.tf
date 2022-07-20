terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"
    }
  }
}

provider "cloudflare" {
  email   = "xxx"
  api_key = "xxx"
}

provider "aws" {
  region = "eu-west-1"
  assume_role {
    role_arn = "arn:aws:iam::529726762838:role/read-static-secrets"
  }
  default_tags {
    tags = var.cx_foundation.tags
  }
  alias = "secrets"
}
