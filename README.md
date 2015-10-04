# checkDhcpd

This script reads ```dhcpd.conf``` file to understand which subnets are defined and then parses ```dhcp.leases``` file in order to understand the utilization of configured subnets.

Single subnets are not supported on this version. Only shared-networks are supported.
