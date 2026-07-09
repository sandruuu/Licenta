provider "digitalocean" {
  token = var.do_token
}

locals {
  common_tags = [
    "trustcloud",
    "trustcloud-digitalocean",
  ]

  gateway_tags      = concat(local.common_tags, ["trustcloud-gateway"])
  resource_tags     = concat(local.common_tags, ["trustcloud-internal-resource"])
  rdp_resource_tags = concat(local.common_tags, ["trustcloud-rdp-resource"])
  private_resource_droplet_ids = concat(
    digitalocean_droplet.internal_resource[*].id,
    digitalocean_droplet.rdp_resource[*].id,
  )
}

resource "digitalocean_vpc" "private_network" {
  name     = var.vpc_name
  region   = var.region
  ip_range = var.vpc_ip_range
}

resource "digitalocean_droplet" "gateway" {
  image    = var.droplet_image
  name     = "trustcloud-gateway"
  region   = var.region
  size     = var.gateway_size
  vpc_uuid = digitalocean_vpc.private_network.id
  ssh_keys = var.ssh_key_fingerprints
  tags     = local.gateway_tags

  monitoring = true
  user_data = templatefile("${path.module}/../cloud-init/gateway.yaml", {
    gateway_compose_b64          = base64encode(file("${path.module}/../gateway/docker-compose.yaml"))
    pdp_ca_pem_base64            = var.pdp_ca_pem_base64
    gateway_image                = var.gateway_image
    pdp_mtls_url                 = var.pdp_mtls_url
    gateway_enrollment_token     = var.gateway_enrollment_token
    gateway_public_port          = var.gateway_public_port
    gateway_public_endpoint_host = var.gateway_public_endpoint_host
  })
}

resource "digitalocean_droplet" "internal_resource" {
  count = var.internal_resource_count

  image    = var.droplet_image
  name     = "trustcloud-resource-${count.index + 1}"
  region   = var.region
  size     = var.resource_size
  vpc_uuid = digitalocean_vpc.private_network.id
  ssh_keys = var.ssh_key_fingerprints
  tags     = local.resource_tags

  monitoring = true
  user_data = templatefile("${path.module}/../cloud-init/internal-resource.yaml", {
    resource_name = "trustcloud-resource-${count.index + 1}"
    resource_port = var.internal_resource_port
  })
}

resource "digitalocean_droplet" "rdp_resource" {
  count = var.rdp_resource_count

  image    = var.droplet_image
  name     = "trustcloud-rdp-${count.index + 1}"
  region   = var.region
  size     = var.resource_size
  vpc_uuid = digitalocean_vpc.private_network.id
  ssh_keys = var.ssh_key_fingerprints
  tags     = local.rdp_resource_tags

  monitoring = true
  user_data = templatefile("${path.module}/../cloud-init/rdp-resource.yaml", {
    rdp_user     = var.rdp_user
    rdp_password = var.rdp_password
  })
}

resource "digitalocean_firewall" "gateway" {
  name        = "trustcloud-gateway-firewall"
  droplet_ids = [digitalocean_droplet.gateway.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_cidrs
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = tostring(var.gateway_public_port)
    source_addresses = var.gateway_allowed_cidrs
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

resource "digitalocean_firewall" "internal_resources" {
  name        = "trustcloud-internal-resources-firewall"
  droplet_ids = local.private_resource_droplet_ids

  inbound_rule {
    protocol         = "tcp"
    port_range       = tostring(var.internal_resource_port)
    source_addresses = ["${digitalocean_droplet.gateway.ipv4_address_private}/32"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = tostring(var.rdp_resource_port)
    source_addresses = ["${digitalocean_droplet.gateway.ipv4_address_private}/32"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["${digitalocean_droplet.gateway.ipv4_address_private}/32"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
