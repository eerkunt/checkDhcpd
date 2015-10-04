# checkDhcpd

This script reads ```dhcpd.conf``` file to understand which subnets are defined and then parses ```dhcp.leases``` file in order to understand the utilization of configured subnets.

Single subnets are not supported on this version. Only shared-networks are supported.

# How to run ?

Before you run. You need to change few lines inside the script ;
```perl
my $dhcpdConfFile  = "/replicated/etc/dhcpd.conf";
my $leasefile = '/replicated/var/state/dhcp/dhcpd.leases';
```
