variable "do_token" {
  description = "DigitalOcean API token."
  type        = string
  sensitive   = true
}

variable "region" {
  description = "DigitalOcean region."
  type        = string
  default     = "fra1"
}

variable "vpc_name" {
  description = "Name of the private VPC used by gateway and internal resources."
  type        = string
  default     = "trustcloud-digitalocean"
}

variable "vpc_ip_range" {
  description = "CIDR for the private VPC."
  type        = string
  default     = "10.40.0.0/24"
}

variable "ssh_key_fingerprints" {
  description = "DigitalOcean SSH key fingerprints allowed on created droplets."
  type        = list(string)
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH into the gateway."
  type        = list(string)
}

variable "gateway_allowed_cidrs" {
  description = "CIDR blocks allowed to reach the public gateway listener."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "droplet_image" {
  description = "Droplet image."
  type        = string
  default     = "ubuntu-22-04-x64"
}

variable "gateway_size" {
  description = "Gateway droplet size."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "resource_size" {
  description = "Internal resource droplet size."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "internal_resource_count" {
  description = "Number of private demo resources."
  type        = number
  default     = 2
}

variable "internal_resource_port" {
  description = "Port exposed by each internal demo resource on the private network."
  type        = number
  default     = 8080
}

variable "rdp_resource_count" {
  description = "Number of private RDP demo resources."
  type        = number
  default     = 1
}

variable "rdp_resource_port" {
  description = "RDP port exposed by private RDP demo resources."
  type        = number
  default     = 3389
}

variable "rdp_user" {
  description = "Demo RDP username."
  type        = string
  default     = "admin"
}

variable "rdp_password" {
  description = "Demo RDP password. Change this in terraform.tfvars for real use."
  type        = string
  sensitive   = true
  default     = "TrustCloudRdp#2026!"
}

variable "gateway_public_port" {
  description = "Public gateway port used by agents."
  type        = number
  default     = 9443
}

variable "gateway_image" {
  description = "Published Docker image for the gateway."
  type        = string
  default     = "laurasandru/trustcloud-gateway:latest"
}

variable "pdp_mtls_url" {
  description = "Public PDP mTLS URL."
  type        = string
  default     = "https://mtls.trust-cloud.dev"
}

variable "gateway_public_endpoint_host" {
  description = "Optional public host for the gateway. Leave empty to use the droplet public IP from metadata."
  type        = string
  default     = ""
}

variable "gateway_enrollment_token" {
  description = "One-time enrollment token created in PDP for this gateway."
  type        = string
  sensitive   = true
}

variable "pdp_ca_pem_base64" {
  description = "Base64-encoded PDP/Vault PKI CA certificate used by the gateway to trust PDP mTLS."
  type        = string
  sensitive   = true
}
