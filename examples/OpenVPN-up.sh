#!/bin/bash

# Exit on any error
set -e

# File to save the original default route
default_route_file="/tmp/openvpn-default-router.txt"

# Fetch the latest Cloudflare IP ranges
cloudflare_ipv4=$(curl -s https://www.cloudflare.com/ips-v4)
cloudflare_ipv6=$(curl -s https://www.cloudflare.com/ips-v6)

# Get the current default gateway
current_default_gateway=$(netstat -rn | grep -E 'default|^0.0.0.0' | awk '{print $2}' | head -n 1)

# Validate current default gateway
if [[ -z "$current_default_gateway" ]]; then
    echo "Error: Could not determine the current default gateway."
    exit 1
fi

# Save the current default gateway to the file
echo "$current_default_gateway" > "$default_route_file"
echo "Current default gateway ($current_default_gateway) saved to $default_route_file."

# Get the tunnel gateway (this assumes OpenVPN assigns a gateway)
vpn_gateway=$(ifconfig | grep -A 1 "tun" | grep "inet " | awk '{print $2}' | head -n 1)

# Validate VPN gateway
if [[ -z "$vpn_gateway" ]]; then
    echo "Error: Could not determine the VPN tunnel gateway."
    exit 1
fi
echo "VPN tunnel gateway: $vpn_gateway"

# Define the CDN gateway (using the current default gateway for CDN routing)
cdn_gateway="$current_default_gateway"

# Additional known Cloudflare IPs not in the official list
additional_cloudflare_ips="172.67.0.0/16 104.21.0.0/16 38.91.106.118/32 38.91.107.85/32 38.91.107.248/32"

# Add routes for Cloudflare IP ranges through the CDN gateway
echo "Adding routes for Cloudflare IP ranges via CDN gateway ($cdn_gateway)..."
for ip in $cloudflare_ipv4 $additional_cloudflare_ips; do
    sudo /sbin/route -n add -net $ip $cdn_gateway 2>/dev/null || true
done

for ip in $cloudflare_ipv6; do
    sudo /sbin/route -n add -inet6 $ip $cdn_gateway 2>/dev/null || true
done

# Change the default route to the VPN tunnel gateway
echo "Setting the default route to the VPN gateway ($vpn_gateway)..."
# Check if the default route exists before trying to delete it
if sudo /sbin/route -n get default >/dev/null 2>&1; then
    sudo /sbin/route -n delete default || true
fi
sudo /sbin/route -n add default $vpn_gateway

echo "Routes configured successfully."

