#!/bin/sh

# Validate input to prevent SQL injection
# Accept IPv4, IPv6, or CIDR notation only

if [ -z "$1" ]; then
  echo "Usage: $0 <ip-address>"
  echo "Example: $0 8.8.8.8"
  echo "Example: $0 2001:db8::1"
  exit 1
fi

# Validate IPv4 (with optional CIDR)
if echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
  : # valid IPv4
# Validate IPv6 (with optional CIDR) - simplified pattern
elif echo "$1" | grep -qE '^[0-9a-fA-F:]+(/[0-9]{1,3})?$'; then
  # Additional check: must contain at least one colon for IPv6
  if echo "$1" | grep -q ':'; then
    : # valid IPv6
  else
    echo "Error: Invalid IP address format"
    echo "Please provide a valid IPv4 or IPv6 address"
    exit 1
  fi
else
  echo "Error: Invalid IP address format"
  echo "Please provide a valid IPv4 or IPv6 address"
  exit 1
fi

psql -e -q -x -c "SELECT block.inetnum, block.netname, block.country, block.description, block.maintained_by, block.created, block.last_modified, block.source FROM block WHERE block.inetnum >> '$1' ORDER BY block.inetnum DESC;" network_info
