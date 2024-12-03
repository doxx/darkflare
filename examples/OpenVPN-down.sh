#!/bin/bash

# Exit on any error
set -e

# Set PATH to include common system binary locations
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# File containing the original default gateway
default_route_file="default-router.txt"

# Fetch the latest Cloudflare IP ranges
cloudflare_ipv4=$(curl -s https://www.cloudflare.com/ips-v4)
cloudflare_ipv6=$(curl -s https://www.cloudflare.com/ips-v6)

# Validate if the original default gateway file exists
if [[ ! -f "$default_route_file" ]]; then
    echo "Error: Original default gateway file ($default_route_file) not found."
    exit 1
fi

# Read the original default gateway from the file
original_default_gateway=$(cat "$default_route_file")

# Validate the original default gateway
if [[ -z "$original_default_gateway" ]]; then
    echo "Error: Original default gateway is empty."
    exit 1
fi
echo "Restoring the original default gateway: $original_default_gateway"

# Remove static routes for Cloudflare IP ranges
echo "Removing routes for Cloudflare IP ranges..."
# Check if IPv4 routes exist before trying to delete them
for ip in $cloudflare_ipv4; do
    if sudo /sbin/route -n get -net $ip >/dev/null 2>&1; then
        sudo /sbin/route -n delete -net $ip 2>/dev/null || true
    fi
done

# Only try to delete IPv6 routes if IPv6 is enabled
if [[ $(sysctl -n net.inet6.ip6.disabled) -eq 0 ]]; then
    for ip in $cloudflare_ipv6; do
        if sudo /sbin/route -n get -inet6 $ip >/dev/null 2>&1; then
            sudo /sbin/route -n delete -inet6 $ip 2>/dev/null || true
        fi
    done
fi

# Restore the original default gateway
echo "Setting the default route back to the original gateway ($original_default_gateway)..."
# Check if we need to restore the default route
current_gateway=$(netstat -rn | grep -E '^default|^0\.0\.0\.0' | awk '{print $2}' | head -n 1)
if [[ "$current_gateway" != "$original_default_gateway" ]]; then
    if sudo /sbin/route -n get default >/dev/null 2>&1; then
        sudo /sbin/route -n delete default || true
    fi
    sudo /sbin/route -n add default $original_default_gateway
fi

echo "Routes removed and original default gateway restored."

