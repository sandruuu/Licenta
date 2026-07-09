output "vpc_id" {
  description = "DigitalOcean VPC ID."
  value       = digitalocean_vpc.private_network.id
}

output "gateway_public_ip" {
  description = "Public IP used by agents to reach the gateway."
  value       = digitalocean_droplet.gateway.ipv4_address
}

output "gateway_private_ip" {
  description = "Private VPC IP of the gateway."
  value       = digitalocean_droplet.gateway.ipv4_address_private
}

output "gateway_public_endpoint" {
  description = "Gateway endpoint to use in PDP if no DNS name is configured."
  value       = "${digitalocean_droplet.gateway.ipv4_address}:${var.gateway_public_port}"
}

output "internal_resource_private_ips" {
  description = "Private IPs to configure as resource hosts in PDP."
  value       = digitalocean_droplet.internal_resource[*].ipv4_address_private
}

output "rdp_resource_private_ips" {
  description = "Private RDP resource IPs to configure as resource hosts in PDP."
  value       = digitalocean_droplet.rdp_resource[*].ipv4_address_private
}

output "pdp_resource_port" {
  description = "Port to use for demo resources in PDP."
  value       = var.internal_resource_port
}

output "pdp_rdp_resource_port" {
  description = "Port to use for RDP demo resources in PDP."
  value       = var.rdp_resource_port
}
