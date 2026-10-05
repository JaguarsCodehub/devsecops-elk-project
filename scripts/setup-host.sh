#!/usr/bin/env bash
# ==============================================================================
# Host Provisioning Script for Ubuntu 22.04 LTS on AWS EC2 (t3.xlarge)
# Installs Docker, sets Elasticsearch kernel parameters, and prepares directory
# ==============================================================================

set -euo pipefail

echo ">>> Updating system packages..."
sudo apt-get update -y && sudo apt-get upgrade -y

echo ">>> Installing prerequisites..."
sudo apt-get install -y ca-certificates curl gnupg lsb-release

echo ">>> Adding Docker official GPG key & repository..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo ">>> Adding current user to docker group..."
sudo usermod -aG docker "$USER"

echo ">>> Setting required kernel parameters for Elasticsearch..."
# Elasticsearch requires vm.max_map_count to be at least 262144
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

echo ">>> Creating project deployment directory..."
sudo mkdir -p /opt/secops-guard
sudo chown -R "$USER":"$USER" /opt/secops-guard

echo "=========================================================="
echo "✅ EC2 Host Provisioning Completed Successfully!"
echo "Please log out and log back in to apply docker group membership."
echo "=========================================================="
